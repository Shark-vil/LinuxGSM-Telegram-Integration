import asyncio
import io
import json
import os
import subprocess
from pathlib import Path
import shlex
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import paramiko
from bot import Bot, Store, command, fingerprint, parse_key, remote, load_servers, local, run, preflight


class Tests(unittest.TestCase):
    def test_admin_binding_and_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory, '@owner')
            self.assertFalse(store.allowed(SimpleNamespace(id=1, username='stranger')))
            self.assertTrue(store.allowed(SimpleNamespace(id=42, username='OWNER')))
            self.assertFalse(store.allowed(SimpleNamespace(id=43, username='owner')))
            store.db.close()
            store = Store(directory, '@changed')
            self.assertTrue(store.allowed(SimpleNamespace(id=42, username=None)))
            self.assertFalse(store.allowed(SimpleNamespace(id=44, username='changed')))
            with store.db:
                store.db.execute('INSERT INTO users VALUES (50)')
            self.assertTrue(store.allowed(SimpleNamespace(id=50, username=None)))
            with store.db:
                store.db.execute('DELETE FROM users WHERE id=50')
            self.assertFalse(store.allowed(SimpleNamespace(id=50, username=None)))
            store.db.close()

    def test_encrypted_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory, '42')
            config = {'name': 'test', 'password': 'secret-password-123', 'key': 'secret-key'}
            store.save(config)
            self.assertEqual(store.server(1), config)
            raw = (Path(directory) / 'bot.sqlite3').read_bytes()
            self.assertNotIn(b'secret-password-123', raw)
            self.assertNotIn(b'secret-key', raw)
            store.db.close()

    def test_shell_quoting_and_allowlist(self):
        path = "/home/game dir/server'; echo hacked; #"
        text = command({'path': path}, 'send', 'say $(touch /tmp/hacked); "hello"')
        left, right = text.split(' && ')
        self.assertEqual(shlex.split(left), ['cd', '--', '/home/game dir'])
        self.assertEqual(shlex.split(right), [path, 'send', 'say $(touch /tmp/hacked); "hello"'])
        for action, value in [('destroy', None), ('send', 'a\nb')]:
            with self.assertRaises(ValueError):
                command({'path': path}, action, value)
        with self.assertRaises(ValueError):
            command({'path': 'relative'}, 'details')

    def test_private_key(self):
        key = paramiko.RSAKey.generate(2048)
        output = io.StringIO()
        key.write_private_key(output, password='passphrase')
        parsed = parse_key(output.getvalue(), 'passphrase')
        self.assertEqual(fingerprint(parsed), fingerprint(key))
        with self.assertRaises(ValueError):
            parse_key(output.getvalue(), 'wrong')

    def test_changed_host_key_never_authenticates(self):
        key = paramiko.RSAKey.generate(2048)
        from unittest.mock import MagicMock
        session = MagicMock()
        session.__enter__.return_value = session
        session.get_remote_server_key.return_value = key
        with patch('bot.transport', return_value=session):
            with self.assertRaises(ValueError):
                remote({'fingerprint': 'different', 'auth': 'password', 'user': 'game', 'password': 'secret'}, 'true')
        session.auth_password.assert_not_called()
        session.auth_publickey.assert_not_called()


class ConfigurationTests(unittest.TestCase):
    def load(self, entries):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'servers.json'
            path.write_text(json.dumps(entries), encoding='utf-8')
            return load_servers(path)

    def test_local_config_stable_ids_and_no_ssh(self):
        entry = {'id': 12, 'name': 'Local', 'transport': 'local', 'path': '/home/game/cs2server'}
        with patch('bot.transport') as ssh:
            config = self.load([entry])
        self.assertEqual(config[-12], entry)
        ssh.assert_not_called()
        with patch('bot.local', return_value=(0, 'ok')) as execute, patch('bot.remote') as ssh:
            self.assertEqual(run(config[-12], 'test'), (0, 'ok'))
            execute.assert_called_once_with('test', 120)
            ssh.assert_not_called()

    def test_config_rejects_duplicates_and_invalid_entries(self):
        entry = {'id': 1, 'name': 'Local', 'transport': 'local', 'path': '/home/game/server'}
        for entries in ([], {}, [None], [entry, entry], [dict(entry, id=True)],
                        [dict(entry, transport='other')], [dict(entry, path='relative')]):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                self.load(entries)

    def test_ssh_password_from_environment_and_key_pin_required(self):
        entry = {'id': 1, 'name': 'LAN', 'transport': 'ssh', 'path': '/home/game/server',
                 'host': '192.168.1.10', 'user': 'game', 'fingerprint': 'SHA256:' + 'a' * 43,
                 'auth': 'password', 'password_env': 'TEST_LAN_PASSWORD'}
        with patch.dict(os.environ, {'TEST_LAN_PASSWORD': 'secret'}):
            self.assertEqual(self.load([entry])[-1]['password'], 'secret')
            self.assertEqual(self.load([entry])[-1]['port'], 22)
            with self.assertRaises(ValueError):
                self.load([dict(entry, fingerprint='')])
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError) as error:
            self.load([entry])
        self.assertNotIn('secret', str(error.exception))

    def test_ssh_key_relative_to_config(self):
        with tempfile.TemporaryDirectory() as directory:
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file(str(Path(directory) / 'key'), password='pass')
            entry = {'id': 1, 'name': 'LAN', 'transport': 'ssh', 'path': '/home/game/server',
                     'host': '192.168.1.10', 'user': 'game', 'fingerprint': 'SHA256:' + 'a' * 43,
                     'auth': 'key', 'key_file': 'key', 'passphrase_env': 'TEST_KEY_PASSWORD'}
            path = Path(directory) / 'servers.json'
            path.write_text(json.dumps([entry]), encoding='utf-8')
            with patch.dict(os.environ, {'TEST_KEY_PASSWORD': 'pass'}):
                config = load_servers(path)[-1]
            self.assertEqual(fingerprint(parse_key(config['key'], config['passphrase'])), fingerprint(key))

    def test_preflight_failure_and_success(self):
        configs = {-1: {'path': '/home/game/server', 'transport': 'local'}}
        with patch('bot.run', side_effect=[(0, ''), (1, 'private output')]), self.assertRaises(ValueError) as error:
            preflight(configs)
        self.assertNotIn('private output', str(error.exception))
        with patch('bot.run', side_effect=[(0, ''), (0, 'details')]) as execute:
            preflight(configs)
            self.assertEqual(execute.call_count, 2)

    def test_config_only_keeps_database_entries_but_hides_them(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory, '42')
            store.save({'name': 'Old SSH'})
            store.configured = {-7: {'name': 'Local'}}
            self.assertEqual(store.servers(True), [(-7, 'Local')])
            self.assertEqual(len(store.servers()), 2)
            self.assertEqual(store.server(-7)['name'], 'Local')
            store.db.close()

    def test_local_process_output_and_timeout_cleanup(self):
        process = MagicMock()
        process.__enter__.return_value = process
        process.pid = 123
        process.stdout.fileno.return_value = 456
        process.wait.return_value = 0
        selector = MagicMock()
        selector.__enter__.return_value = selector
        selector.select.return_value = [object()]
        with patch('bot.os.name', 'posix'), patch('bot.os.geteuid', return_value=1000, create=True), \
             patch('bot.Path.exists', return_value=False), patch('bot.subprocess.Popen', return_value=process) as popen, \
             patch('bot.selectors.DefaultSelector', return_value=selector), \
             patch('bot.os.read', side_effect=[b'hello', b'']):
            self.assertEqual(local('echo hello'), (0, 'hello'))
            self.assertEqual(popen.call_args.args[0], ['/bin/bash', '-c', 'echo hello'])
            self.assertTrue(popen.call_args.kwargs['start_new_session'])
            with patch('bot.time.monotonic', side_effect=[0, 2]), \
                 patch('bot.os.killpg', create=True) as kill, patch('bot.signal.SIGKILL', 9, create=True), self.assertRaises(TimeoutError):
                local('sleep 60', timeout=1)
            kill.assert_called_once()

    def test_local_rejects_root(self):
        with patch('bot.os.name', 'posix'), patch('bot.os.geteuid', return_value=0, create=True), \
             patch('bot.subprocess.Popen') as popen, self.assertRaises(ValueError):
            local('true')
        popen.assert_not_called()


class FlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(self.directory.name, '42')
        self.bot = Bot(self.store)
        self.message = SimpleNamespace(reply_text=AsyncMock(), reply_document=AsyncMock())
        self.update = SimpleNamespace(effective_user=SimpleNamespace(id=42, username=None),
                                      effective_chat=SimpleNamespace(type='private'), effective_message=self.message)

    async def asyncTearDown(self):
        self.store.db.close()
        self.directory.cleanup()

    async def test_validation_only_saves_success(self):
        state = {'step': 'path', 'config': {'name': 'server'}}
        with patch('bot.remote', side_effect=[(0, ''), (1, 'failure')]):
            await self.bot.validate(self.update, state, '/home/game/cs2server')
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM servers').fetchone()[0], 0)
        self.assertEqual(state['step'], 'path')
        with patch('bot.remote', side_effect=[(0, ''), (0, 'details')]):
            await self.bot.validate(self.update, state, '/home/game/cs2server')
        self.assertEqual(self.store.server(1)['path'], '/home/game/cs2server')

    async def test_private_chat_only(self):
        self.update.effective_chat.type = 'group'
        self.assertFalse(await self.bot.authorized(self.update))
        self.assertIsNone(self.store.admin_id())

    async def test_parallel_command_rejected(self):
        self.bot.locks[1] = asyncio.Lock()
        async with self.bot.locks[1]:
            with patch('bot.remote') as run:
                await self.bot.execute(self.update, 1, 'start')
                run.assert_not_called()

    async def test_non_admin_cannot_add_server(self):
        self.store.allowed(self.update.effective_user)
        with self.store.db:
            self.store.db.execute('INSERT INTO users VALUES (43)')
        self.update.effective_user = SimpleNamespace(id=43, username=None)
        self.update.callback_query = SimpleNamespace(answer=AsyncMock(), data='add', message=self.message)
        await self.bot.callback(self.update, None)
        self.assertNotIn(43, self.bot.states)


    async def test_config_only_blocks_old_buttons_and_addition(self):
        self.bot.config_only = True
        self.store.allowed(self.update.effective_user)
        self.update.callback_query = SimpleNamespace(answer=AsyncMock(), data='add', message=self.message)
        await self.bot.callback(self.update, None)
        self.assertNotIn(42, self.bot.states)
        with patch('bot.run') as execute:
            await self.bot.execute(self.update, 1, 'start')
            execute.assert_not_called()
        await self.bot.menu(self.update, None)
        markup = self.message.reply_text.call_args.kwargs['reply_markup']
        self.assertNotIn('add', [button.callback_data for row in markup.inline_keyboard for button in row])


if __name__ == '__main__':
    unittest.main()
