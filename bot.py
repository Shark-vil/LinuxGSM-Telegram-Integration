import asyncio
import base64
import hashlib
import io
import ipaddress
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import subprocess
import shlex
import socket
import sqlite3
import time

import paramiko
from cryptography.fernet import Fernet
from telegram import InlineKeyboardButton as Button, InlineKeyboardMarkup as Markup
from telegram.error import TelegramError
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, MessageHandler, filters

ACTIONS = {'details': 'Информация', 'start': 'Запустить', 'stop': 'Остановить',
           'restart': 'Перезапустить', 'check-update': 'Проверить обновления',
           'update': 'Обновить', 'backup': 'Резервная копия', 'send': 'Команда консоли'}
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
DISCOVER = r'''find "$HOME" -maxdepth 5 -type f -executable ! -path '*/serverfiles/*' ! -path '*/lgsm/*' ! -path '*/.steam/*' -print0 2>/dev/null | while IFS= read -r -d '' f; do
if head -c 8192 "$f" | grep -q 'gameservername=' && head -c 8192 "$f" | grep -q 'LinuxGSM'; then
case "$(basename "$f")" in linuxgsm.sh) ;; *) printf '%s\n' "$f" ;; esac
fi
done'''


class Store:
    def __init__(self, directory, admin):
        if not (admin.isdigit() and int(admin) > 0) and not re.fullmatch(r'@?[A-Za-z][A-Za-z0-9_]{4,31}', admin):
            raise ValueError('BOT_ADMIN: положительный userid или @username')
        self.admin = admin
        self.configured = {}
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = directory / 'secret.key'
        if not key.exists():
            with key.open('xb') as f:
                f.write(Fernet.generate_key())
            key.chmod(0o600)
        self.cipher = Fernet(key.read_bytes())
        self.db = sqlite3.connect(directory / 'bot.sqlite3')
        self.db.executescript('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS servers (id INTEGER PRIMARY KEY, name TEXT, payload BLOB);''')
        self.db.commit()

    def admin_id(self):
        row = self.db.execute("SELECT value FROM settings WHERE key='admin_id'").fetchone()
        return int(row[0]) if row else None

    def allowed(self, user):
        admin_id = self.admin_id()
        if admin_id is None:
            match = (str(user.id) == self.admin if self.admin.isdigit() else
                     bool(user.username) and user.username.lower() == self.admin.lstrip('@').lower())
            if match:
                with self.db:
                    self.db.execute("INSERT INTO settings VALUES ('admin_id', ?)", (str(user.id),))
                admin_id = user.id
        return user.id == admin_id or self.db.execute('SELECT 1 FROM users WHERE id=?', (user.id,)).fetchone() is not None

    def save(self, config):
        with self.db:
            self.db.execute('INSERT INTO servers(name,payload) VALUES (?,?)',
                            (config['name'], self.cipher.encrypt(json.dumps(config).encode())))

    def server(self, sid):
        if sid < 0:
            if sid not in self.configured:
                raise ValueError('Сервер удалён из конфигурации')
            return self.configured[sid]
        row = self.db.execute('SELECT payload FROM servers WHERE id=?', (sid,)).fetchone()
        if not row:
            raise ValueError('Сервер удалён')
        return json.loads(self.cipher.decrypt(row[0]))

    def servers(self, config_only=False):
        rows = [(sid, config['name']) for sid, config in self.configured.items()]
        if not config_only:
            rows += list(self.db.execute('SELECT id,name FROM servers ORDER BY id'))
        return rows


def load_servers(filename):
    """Stable negative IDs keep file entries separate from interactive entries."""
    source = Path(filename).resolve()
    try:
        entries = json.loads(source.read_text(encoding='utf-8-sig'))
    except (OSError, ValueError):
        raise ValueError('Не удалось прочитать SERVERS_FILE: нужен JSON-массив') from None
    if not isinstance(entries, list) or not entries:
        raise ValueError('SERVERS_FILE должен содержать непустой JSON-массив')
    configs = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError('Каждый сервер должен быть JSON-объектом')
        config = entry.copy()
        sid = config.get('id')
        if type(sid) is not int or not 1 <= sid <= 2147483647 or -sid in configs:
            raise ValueError('У серверов должны быть уникальные положительные числовые id')
        if not isinstance(config.get('name'), str) or not config['name'].strip() or len(config['name']) > 80:
            raise ValueError(f'Сервер {sid}: требуется name от 1 до 80 символов')
        if not isinstance(config.get('path'), str):
            raise ValueError(f'Сервер {sid}: требуется абсолютный path')
        command(config, 'details')
        mode = config.get('transport')
        if mode not in ('local', 'ssh'):
            raise ValueError(f'Сервер {sid}: transport должен быть local или ssh')
        if mode == 'ssh':
            try:
                config['host'] = str(ipaddress.ip_address(config['host']))
                port = config.setdefault('port', 22)
                if type(port) is not int or not 1 <= port <= 65535:
                    raise ValueError()
                if not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_.-]{0,63}', config['user']) or config['user'] == 'root':
                    raise ValueError()
                if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', config['fingerprint']):
                    raise ValueError()
                if config['auth'] == 'password':
                    config['password'] = os.environ[config['password_env']]
                    if not config['password']:
                        raise ValueError()
                elif config['auth'] == 'key':
                    config['key'] = (source.parent / config['key_file']).read_text(encoding='utf-8')
                    config['passphrase'] = os.environ[config['passphrase_env']] if config.get('passphrase_env') else None
                    parse_key(config['key'], config['passphrase'])
                else:
                    raise ValueError()
            except (KeyError, TypeError, ValueError, OSError):
                raise ValueError(f'Сервер {sid}: проверьте IP, порт, user, fingerprint и SSH-реквизиты') from None
        configs[-sid] = config
    return configs


def fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


def transport(config):
    sock = socket.create_connection((config['host'], config['port']), timeout=15)
    session = paramiko.Transport(sock)
    session.auth_timeout = 15
    session.banner_timeout = 15
    try:
        session.start_client(timeout=15)
        return session
    except BaseException:
        session.close()
        raise


def probe(config):
    with transport(config) as session:
        return fingerprint(session.get_remote_server_key())


def parse_key(value, password=None):
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(value), password=password)
        except (paramiko.SSHException, ValueError):
            pass
    raise ValueError('Не удалось прочитать ключ: проверьте формат и пароль ключа')


def command(config, action, argument=None):
    if action not in ACTIONS:
        raise ValueError('Недопустимая команда')
    path = config['path']
    if not path.startswith('/') or '\n' in path or '\r' in path:
        raise ValueError('Нужен абсолютный путь к скрипту')
    args = [path, action]
    if action == 'send':
        if not argument or len(argument) > 1000 or '\n' in argument or '\r' in argument:
            raise ValueError('Команда консоли: одна строка до 1000 символов')
        args.append(argument)
    return 'cd -- ' + shlex.quote(str(PurePosixPath(path).parent)) + ' && ' + shlex.join(args)


def remote(config, cmd, timeout=120):
    with transport(config) as session:
        if fingerprint(session.get_remote_server_key()) != config['fingerprint']:
            raise ValueError('SSH-ключ сервера изменился. Проверьте сервер и добавьте его заново')
        if config['auth'] == 'password':
            session.auth_password(config['user'], config['password'], fallback=False)
        else:
            session.auth_publickey(config['user'], parse_key(config['key'], config.get('passphrase')))
        channel = session.open_session(timeout=15)
        channel.settimeout(15)
        channel.exec_command(cmd)
        channel.shutdown_write()
        output = bytearray()
        deadline = time.monotonic() + timeout
        while True:
            for ready, read in ((channel.recv_ready, channel.recv), (channel.recv_stderr_ready, channel.recv_stderr)):
                if ready():
                    data = read(32768)
                    if len(output) < 512_000:
                        output.extend(data[:512_000 - len(output)])
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if time.monotonic() > deadline:
                channel.close()
                raise TimeoutError()
            time.sleep(0.03)
        return channel.recv_exit_status(), ANSI.sub('', output.decode('utf-8', errors='replace')).replace('\x00', '')


def local(cmd, timeout=120):
    if os.name != 'posix' or os.geteuid() == 0:
        raise ValueError('Локальный режим требует Linux и запуска от пользователя LinuxGSM, не root')
    if Path('/.dockerenv').exists():
        raise ValueError('Локальный режим запускайте на хосте вне Docker-контейнера')
    output = bytearray()
    with subprocess.Popen(['/bin/bash', '-c', cmd], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          start_new_session=True) as process:
        try:
            deadline = time.monotonic() + timeout
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError()
                    if not selector.select(min(remaining, 0.25)):
                        continue
                    data = os.read(process.stdout.fileno(), 32768)
                    if not data:
                        break
                    if len(output) < 512_000:
                        output.extend(data[:512_000 - len(output)])
            code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except BaseException as exc:
            # Kill the command's process group so a timeout leaves no shell child behind.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            if isinstance(exc, subprocess.TimeoutExpired):
                raise TimeoutError() from None
            raise
    return code, ANSI.sub('', output.decode('utf-8', errors='replace')).replace('\x00', '')


def run(config, cmd, timeout=120):
    mode = config.get('transport', 'ssh')
    if mode == 'local':
        return local(cmd, timeout)
    if mode == 'ssh':
        return remote(config, cmd, timeout)
    raise ValueError('Неизвестный способ подключения')


def script_check(path):
    return ('test -x ' + shlex.quote(path) + ' && head -c 8192 ' + shlex.quote(path)
            + " | grep -q 'LinuxGSM'")


def preflight(configs):
    for sid, config in configs.items():
        try:
            code, _ = run(config, script_check(config['path']), 30)
            if code:
                raise ValueError('Не найден исполняемый скрипт LinuxGSM')
            code, _ = run(config, command(config, 'details'), 120)
            if code:
                raise ValueError(f'Проверка details завершилась с кодом {code}')
        except Exception as exc:
            raise ValueError(f'Сервер {abs(sid)}: ' + safe_error(exc)) from None


def keyboard(rows):
    return Markup([[Button(label, callback_data=data) for label, data in row] for row in rows])


def safe_error(exc):
    if type(exc) is ValueError:
        return str(exc)[:500]
    if isinstance(exc, TimeoutError):
        return 'Тайм-аут. Команда могла продолжить работу: проверьте details перед повтором.'
    if isinstance(exc, paramiko.AuthenticationException):
        return 'Ошибка SSH-аутентификации. Проверьте пользователя, пароль или ключ.'
    return f'Операция не выполнена ({type(exc).__name__}). Проверьте подключение и настройки.'


class Bot:
    def __init__(self, store, config_only=False):
        self.config_only = config_only
        self.store = store
        self.states = {}
        self.locks = {}

    async def authorized(self, update):
        if not update.effective_chat or update.effective_chat.type != 'private':
            return False
        if not self.store.allowed(update.effective_user):
            await update.effective_message.reply_text(f'Нет доступа. Ваш Telegram ID: {update.effective_user.id}')
            return False
        return True

    async def menu(self, update, context):
        if not await self.authorized(update):
            return
        self.states.pop(update.effective_user.id, None)
        rows = [[(name, f'server:{sid}')] for sid, name in self.store.servers(self.config_only)]
        if update.effective_user.id == self.store.admin_id():
            if not self.config_only:
                rows.append([('Добавить сервер', 'add')])
            rows.append([('Пользователи', 'users')])
        await update.effective_message.reply_text('Выберите сервер. /cancel — отмена ввода.', reply_markup=keyboard(rows) if rows else None)

    async def panel(self, message, sid):
        if self.config_only and sid >= 0:
            return
        config = self.store.server(sid)
        rows = [[(label, f'act:{sid}:{action}')] for action, label in ACTIONS.items()]
        rows.append([('Список серверов', 'menu')])
        await message.reply_text(config['name'], reply_markup=keyboard(rows))

    async def result(self, message, code, output):
        text = f'Код завершения: {code}\n{output or "(нет вывода)"}'
        if len(text.encode('utf-16-le')) <= 7800:
            await message.reply_text(text)
        else:
            await message.reply_text('Вывод в файле (лимит 512 КБ).')
            await message.reply_document(document=io.BytesIO(text.encode()), filename='linuxgsm-output.txt')

    async def execute(self, update, sid, action, argument=None):
        if self.config_only and sid >= 0:
            return
        lock = self.locks.setdefault(sid, asyncio.Lock())
        if lock.locked():
            await update.effective_message.reply_text('На этом сервере уже выполняется команда.')
            return
        async with lock:
            if not self.store.allowed(update.effective_user):
                return
            config = self.store.server(sid)
            await update.effective_message.reply_text(f'{config["name"]}: {action}…')
            try:
                code, output = await asyncio.to_thread(run, config, command(config, action, argument), 900)
                await self.result(update.effective_message, code, output)
            except Exception as exc:
                await update.effective_message.reply_text(safe_error(exc))

    async def callback(self, update, context):
        q = update.callback_query
        await q.answer()
        if not await self.authorized(update):
            return
        uid, data = update.effective_user.id, q.data
        if data == 'menu':
            return await self.menu(update, context)
        if data.startswith('server:'):
            return await self.panel(q.message, int(data.split(':')[1]))
        if data.startswith(('act:', 'run:')):
            prefix, sid, action = data.split(':')
            sid = int(sid)
            if self.config_only and sid >= 0:
                return
            if action not in ACTIONS:
                return
            if action == 'send':
                self.states[uid] = {'step': 'console', 'sid': sid}
                await q.message.reply_text('Введите одну команду игровой консоли. /cancel — отмена.')
            elif prefix == 'act' and action not in ('details', 'check-update'):
                self.states[uid] = {'step': 'confirm', 'sid': sid, 'action': action}
                await q.message.reply_text(f'Выполнить {action}?', reply_markup=keyboard([[('Да', f'run:{sid}:{action}'), ('Отмена', 'menu')]]))
            else:
                if prefix == 'run' and self.states.pop(uid, {}) != {'step': 'confirm', 'sid': sid, 'action': action}:
                    return
                context.application.create_task(self.execute(update, sid, action), update=update)
            return
        if uid != self.store.admin_id():
            return
        state = self.states.get(uid, {})
        if data == 'add' and not self.config_only:
            self.states[uid] = {'step': 'name', 'config': {}}
            await q.message.reply_text('Название сервера:')
        elif data == 'users':
            ids = [str(row[0]) for row in self.store.db.execute('SELECT id FROM users')]
            await q.message.reply_text('Пользователи: ' + (', '.join(ids) or 'нет'), reply_markup=keyboard([[('Добавить', 'user:add'), ('Удалить', 'user:remove')]]))
        elif data in ('user:add', 'user:remove'):
            self.states[uid] = {'step': data}
            await q.message.reply_text('Введите числовой Telegram ID пользователя:')
        elif data.startswith('auth:') and state.get('step') == 'auth' and data[5:] in ('password', 'key'):
            state['config']['auth'] = data[5:]
            state['step'] = data[5:]
            await q.message.reply_text('Отправьте пароль SSH:' if data[5:] == 'password' else 'Пришлите приватный SSH-ключ как файл (до 64 КБ):')
        elif data == 'trust' and state.get('step') == 'trust':
            state['step'] = 'auth'
            await q.message.reply_text('Способ входа:', reply_markup=keyboard([[('Пароль', 'auth:password'), ('SSH-ключ', 'auth:key')]]))
        elif data.startswith('path:') and state.get('step') == 'path':
            index = int(data.split(':')[1])
            if 0 <= index < len(state.get('paths', [])):
                await self.validate(update, state, state['paths'][index])

    async def discover(self, update, state):
        state['step'] = 'busy'
        await update.effective_message.reply_text('Проверяю вход и ищу установленные LinuxGSM-серверы…')
        code, output = await asyncio.to_thread(run, state['config'], 'bash -c ' + shlex.quote(DISCOVER), 90)
        paths = [p for p in output.splitlines() if p.startswith('/') and len(p) < 4096][:30]
        state.update(step='path', paths=paths)
        rows = [[(p[-60:], f'path:{i}')] for i, p in enumerate(paths)]
        await update.effective_message.reply_text('Выберите скрипт или введите абсолютный путь. Поиск: $HOME, глубина 5.', reply_markup=keyboard(rows) if rows else None)

    async def validate(self, update, state, path):
        state['config']['path'] = path
        cmd = command(state['config'], 'details')
        state['step'] = 'busy'
        await update.effective_message.reply_text('Тестовый запуск details…')
        # Verify the manually supplied file too, before executing it.
        check = script_check(path)
        code, _ = await asyncio.to_thread(run, state['config'], check, 30)
        if code:
            state['step'] = 'path'
            raise ValueError('Не найден исполняемый скрипт LinuxGSM. Введите путь повторно')
        code, output = await asyncio.to_thread(run, state['config'], cmd, 120)
        await self.result(update.effective_message, code, output)
        if code:
            state['step'] = 'path'
            await update.effective_message.reply_text('Сервер не сохранён. Исправьте причину и введите путь повторно либо /cancel.')
            return
        self.store.save(state['config'])
        await self.menu(update, None)
        await update.effective_message.reply_text('Сервер проверен и сохранён.')

    async def text(self, update, context):
        if not await self.authorized(update):
            return
        uid = update.effective_user.id
        state = self.states.get(uid)
        if not state:
            return await self.menu(update, context)
        value = update.effective_message.text or ''
        step = state['step']
        if step == 'console':
            command(self.store.server(state['sid']), 'send', value)
            self.states.pop(uid)
            context.application.create_task(self.execute(update, state['sid'], 'send', value), update=update)
            return
        if uid != self.store.admin_id():
            return
        if step.startswith('user:'):
            if not value.isdigit() or int(value) <= 0:
                raise ValueError('Введите положительный числовой ID')
            with self.store.db:
                if step == 'user:add':
                    self.store.db.execute('INSERT OR IGNORE INTO users VALUES (?)', (int(value),))
                else:
                    self.store.db.execute('DELETE FROM users WHERE id=?', (int(value),))
            return await self.menu(update, context)
        config = state.get('config', {})
        if step == 'name':
            if not value.strip() or len(value) > 80:
                raise ValueError('Название: от 1 до 80 символов')
            config['name'] = value.strip()
            state['step'] = 'host'
            await update.effective_message.reply_text('IP-адрес SSH-сервера (IPv4 или IPv6):')
        elif step == 'host':
            config['host'] = str(ipaddress.ip_address(value.strip()))
            state['step'] = 'port'
            await update.effective_message.reply_text('SSH-порт, например 22:')
        elif step == 'port':
            if not value.isdigit() or not 1 <= int(value) <= 65535:
                raise ValueError('Порт: число от 1 до 65535')
            config['port'] = int(value)
            state['step'] = 'user'
            await update.effective_message.reply_text('SSH-пользователь, владелец LinuxGSM (не root):')
        elif step == 'user':
            if not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_.-]{0,63}', value) or value == 'root':
                raise ValueError('Нужен корректный пользователь LinuxGSM, не root')
            config['user'] = value
            config['fingerprint'] = await asyncio.to_thread(probe, config)
            state['step'] = 'trust'
            await update.effective_message.reply_text(f'SSH-отпечаток:\n{config["fingerprint"]}\nСверьте с выводом на сервере:\nssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256\nДля другого типа ключа используйте соответствующий .pub.', reply_markup=keyboard([[('Доверять ключу', 'trust'), ('Отмена', 'menu')]]))
        elif step == 'password':
            if not value or len(value) > 4096:
                raise ValueError('Пришлите непустой пароль')
            config['password'] = value
            await self.erase_secret(update)
            await self.discover(update, state)
        elif step == 'key':
            doc = update.effective_message.document
            if not doc or not doc.file_size or doc.file_size > 65536:
                raise ValueError('Пришлите ключ файлом размером до 64 КБ')
            file = await doc.get_file()
            contents = await file.download_as_bytearray()
            if len(contents) > 65536:
                raise ValueError('Ключ слишком большой')
            config['key'] = contents.decode('utf-8')
            await self.erase_secret(update)
            state['step'] = 'passphrase'
            await update.effective_message.reply_text('Пароль приватного ключа или «-», если ключ без пароля:')
        elif step == 'passphrase':
            config['passphrase'] = None if value == '-' else value
            await self.erase_secret(update)
            parse_key(config['key'], config['passphrase'])
            await self.discover(update, state)
        elif step == 'path':
            await self.validate(update, state, value)
        else:
            await update.effective_message.reply_text('Используйте предложенные кнопки либо /cancel.')

    async def erase_secret(self, update):
        try:
            await update.effective_message.delete()
        except TelegramError:
            await update.effective_message.reply_text('Telegram не позволил удалить сообщение с секретом; удалите его вручную.')

    async def error(self, update, context):
        # Updates and exception messages can contain credentials.
        logging.error('Handler failed: %s', type(context.error).__name__)
        if update and update.effective_message:
            state = self.states.get(update.effective_user.id, {})
            if state.get('step') == 'busy':
                self.states.pop(update.effective_user.id, None)
            await update.effective_message.reply_text(safe_error(context.error) + '\n/cancel — начать заново.')


def main():
    os.umask(0o077)
    logging.basicConfig(level=logging.WARNING)
    store = Store(os.environ.get('DATA_DIR', 'data'), os.environ['BOT_ADMIN'].strip())
    filename = os.environ.get('SERVERS_FILE', '').strip()
    flag = os.environ.get('CONFIG_ONLY', 'false').strip().lower()
    if flag not in ('true', 'false'):
        raise ValueError('CONFIG_ONLY: true или false')
    config_only = flag == 'true'
    if config_only and not filename:
        raise ValueError('CONFIG_ONLY=true требует SERVERS_FILE')
    if filename:
        configs = load_servers(filename)
        preflight(configs)
        store.configured = configs
    bot = Bot(store, config_only=config_only)
    app = Application.builder().token(os.environ['BOT_TOKEN']).build()
    app.add_handler(CommandHandler(['start', 'servers', 'cancel'], bot.menu))
    app.add_handler(CallbackQueryHandler(bot.callback))
    app.add_handler(MessageHandler((filters.TEXT & ~filters.COMMAND) | filters.Document.ALL, bot.text))
    app.add_error_handler(bot.error)
    app.run_polling(drop_pending_updates=True)


if __name__ == '__main__':
    main()

