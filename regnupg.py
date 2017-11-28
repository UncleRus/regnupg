# -*- coding: utf-8 -*-

__version__ = '0.4.4'


import sys
import logging
import threading
import subprocess
import codecs
import locale
import os
import socket
import tempfile


_py3k = sys.version_info[0] >= 3


try:
    from io import BytesIO
    _BinaryStream = BytesIO
except ImportError:
    from StringIO import StringIO
    _BinaryStream = StringIO


try:
    _win = subprocess.mswindows
except AttributeError:
    _win = subprocess._mswindows

# Hide M$Win console
if _win:
    _startup_info = subprocess.STARTUPINFO()
    try:
        subprocess.STARTF_USESHOWWINDOW
        _sp = subprocess
    except AttributeError:
        import _subprocess
        _sp = _subprocess
    _startup_info.dwFlags |= _sp.STARTF_USESHOWWINDOW
    _startup_info.wShowWindow = _sp.SW_HIDE
    _popen_kwargs = {'startupinfo': _startup_info}
else:
    _popen_kwargs = {}


log = logging.getLogger(__name__)
if not log.handlers:
    log.addHandler(logging.NullHandler())


def to_int(value, default=0):
    try:
        return int(value)
    except ValueError:
        return default


def make_list(arg):
    return arg if isinstance(arg, (list, tuple, set, frozenset)) else [arg]


def to_timestamp(value):
    # FIXME: Обрабатывать ISO-формат
    if 'T' not in value:
        return to_int(value)
    return value


class Error (Exception):

    def __init__(self, message, err):
        self.raw = '\n'.join((line.strip()
                              for line in err if line.startswith('gpg:')))
        super(Error, self).__init__(message)


class GeneralError (Error):

    def __init__(self, err):
        super(GeneralError, self).__init__('\n'.join((line.strip()
                                                      for line in err if line.startswith('gpg:'))), err)


class NoDataError (Error):

    _reasons = {
        1: 'No armored data',
        2: 'Expected a packet but did not found one',
        3: 'Invalid packet found, this may indicate a non OpenPGP message',
        4: 'Signature expected but not found'
    }

    def __init__(self, code, err):
        super(NoDataError, self).__init__(
            self._reasons.get(code, 'No valid data found'), err)


class UnknownStatusError (Error):

    def __init__(self, code, err):
        super(UnknownStatusError, self).__init__(
            'Unknown status code "%s"' % code, err)


class KeyDeleteError (Error):

    _reasons = {
        2: 'Must delete secret key first',
        3: 'Ambigious specification'
    }

    def __init__(self, code, err):
        super(KeyDeleteError, self).__init__(
            self._reasons.get(code, 'Unknown error'), err)


class InvalidMemberError (Error):

    _reasons = (
        'No specific reason given',
        'Not found',
        'Ambigious specification',
        'Wrong key usage',
        'Key revoked',
        'Key expired',
        'No CRL known',
        'CRL too old',
        'Policy mismatch',
        'Not a secret key',
        'Key not trusted',
        'Missing certificate',
        'Missing issuer certificate'
    )

    def __init__(self, err, message, reason=None, who=None):
        if reason is not None:
            message = message % (reason, who)
            reason = self._reasons[to_int(reason)]
        super(InvalidMemberError, self).__init__(message, err)


class SmartcardError (Error):

    _reasons = ('Unspecified error', 'Canceled', 'Bad PIN')

    def __init__(self, reason, err):
        super(SmartcardError, self).__init__(self._reasons[reason], err)


class PassphraseError (Error):
    pass


class AlgorithmError (Error):
    pass


class GpgKeyError (Error):
    pass


class DecryptionError (Error):
    pass


class AttributedDict (dict):

    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class Result (object):

    def __init__(self):
        self.err = None
        self.status = None
        self.data = None
        self.processors = {
            'IMPORT_OK': None, 'NEWSIG': None, 'KEY_CONSIDERED': None, 'PINENTRY_LAUNCHED': None,
            'NODATA': self._nodata,
            'SC_OP_FAILURE': self._sc_op_failure,
            'INV_SGNR': self._inv_member,
            'INV_RECP': self._inv_member,
            'NO_SGNR': self._no_member,
            'NO_RECP': self._no_member,
            'NO_SECKEY': self._no_seckey,
            'NO_PUBKEY': self._no_pubkey,
            'MISSING_PASSPHRASE': self._missing_passphrase,
            'BAD_PASSPHRASE': self._bad_passphrase,
            'DECRYPTION_FAILED': self._decryption_failed,
            'FAILURE': self._failure,
        }

    def handle(self):
        for status, value in self.status:
            log.debug('Result.handle(): processing status %s', status)
            if status in self.processors:
                if self.processors[status]:
                    self.processors[status](status, value)
            else:
                raise UnknownStatusError(status, self.err)

    def _failure(self, code, value):
        raise GeneralError(self.err)

    def _nodata(self, code, value):
        raise NoDataError(to_int(value), self.err)

    def _sc_op_failure(self, code, value):
        raise SmartcardError(to_int(value), self.err)

    def _inv_member(self, code, value):
        reason, who = value.split()
        raise InvalidMemberError(self.err, 'Invalid signer: %s (%s)' if code == 'INV_SGNR' else 'Invalid recipient: %s (%s)', reason, who)

    def _no_member(self, code, value):
        raise InvalidMemberError(
            self.err, 'No signers are usable' if code == 'INV_SGNR' else 'No recipients are usable')

    def _no_seckey(self, code, value):
        raise GpgKeyError(
            'The secret key (%s) is not available' % value, self.err)

    def _no_pubkey(self, code, value):
        raise GpgKeyError(
            'The public key (%s) is not available' % value, self.err)

    def _missing_passphrase(self, code, value):
        raise PassphraseError('Missing passphrase', self.err)

    def _bad_passphrase(self, code, value):
        raise PassphraseError('Bad passphrase for key %s' % value, self.err)

    def _decryption_failed(self, code, value):
        raise DecryptionError('The symmetric decryption failed', self.err)

    if _py3k:
        def __str__(self):
            return self.data
    else:
        def __unicode__(self):
            return self.data

        def __str__(self):
            # FIXME: исправить на нормальный способ определения кодировки
            return self.data.encode('utf8')

    def __nonzero__(self):
        return bool(self.data)

    __bool__ = __nonzero__


class ImportResult (Result):

    _attrs = ('count', 'no_user_id', 'imported', 'imported_rsa', 'unchanged',
              'n_uids', 'n_subk', 'n_sigs', 'n_revoc', 'sec_read', 'sec_imported',
              'sec_dups', 'skipped_new_keys', 'not_imported')

    _ok_reasons = {
        1: 'Entirely new key',
        2: 'New user IDs',
        4: 'New signatures',
        8: 'New subkeys',
        16: 'Contains private key'
    }

    _problem_reasons = {
        1: 'Invalid certificate',
        2: 'Issuer certificate missing',
        3: 'Certificate chain too long',
        4: 'Error storing certificate'
    }

    def __init__(self):
        super(ImportResult, self).__init__()
        self.results = []
        self.processors.update({
            'IMPORTED': None,
            'KEYEXPIRED': None,
            'SIGEXPIRED': None,
            'IMPORT_OK': self._import_ok,
            'IMPORT_PROBLEM': self._import_problem,
            'IMPORT_RES': self._import_res
        })
        self.counters = AttributedDict()

    def _add_result(self, fingerprint, reason, problem):
        reason = int(reason)
        problem = int(problem) if problem else None
        if fingerprint:
            result_text = [text for bit, text in self._ok_reasons.items() if bit & reason] if reason > 0 else ['No actually changed']
        else:
            result_text = ()
        self.results.append(AttributedDict(
            fingerprint=fingerprint,
            imported=reason > 0,
            result=reason,
            result_text=result_text,
            problem=problem,
            problem_text=self._problem_reasons.get(problem) if problem else None
        ))

    def _import_ok(self, code, value):
        reason, fingerprint = value.split()
        self._add_result(fingerprint, reason, None)

    def _import_problem(self, code, value):
        try:
            reason, fingerprint = value.split()
        except ValueError:
            reason, fingerprint = value, None
        self._add_result(fingerprint, -1, reason)

    def _import_res(self, code, value):
        values = value.split()
        self.counters.update({name: int(values[i]) for i, name in enumerate(self._attrs)})

    def __nonzero__(self):
        return bool(self.results)

    __bool__ = __nonzero__


class ListResult (Result):

    _pub_fields = ('trust', 'length', 'algorithm', 'id',
                   'date', 'expires', '_', 'ownertrust', 'uid')
    _int_fields = ('length', 'algorithm', 'date', 'expires')

    def __init__(self):
        super(ListResult, self).__init__()
        self.keys = {}

    def _add_key(self, fields):
        result = AttributedDict({name: (to_int(fields[i]) if name in self._int_fields else fields[i])
                                 for i, name in enumerate(self._pub_fields) if name != '_'})
        result.uids = [result.uid] if result.uid else []
        result.subkeys = []
        del result['uid']
        return result

    def handle(self):
        if not self.data:
            return

        for line in self.data.splitlines():
            log.debug('ListResult.handle(): processing %s', line)
            line = line.strip()
            if not line:
                continue
            fields = line.split(':')
            key = fields[0]
            del fields[0]
            if key in ('pub', 'sec'):
                self._current = self._add_key(fields)
            elif key == 'fpr':
                self._current.fingerprint = fields[8]
                self.keys[self._current.fingerprint] = self._current
            elif key == 'uid':
                self._current.uids.append(fields[8])
            elif key == 'sub':
                self._current.subkeys.append((fields[3], fields[10]))

    def __nonzero__(self):
        return bool(self.keys)

    __bool__ = __nonzero__


class ExportResult (Result):

    def handle(self):
        pass


class DeleteResult (Result):

    def __init__(self):
        super(DeleteResult, self).__init__()
        self.processors = {
            'KEY_CONSIDERED': None,
            'DELETE_PROBLEM': self._delete_problem
        }

    def _delete_problem(self, code, value):
        value = to_int(value)
        if value != 1:
            raise KeyDeleteError(value, self.err)


class GenKeyResult (Result):

    def __init__(self):
        super(GenKeyResult, self).__init__()
        self.type = None
        self.fingerprint = None
        self.processors.update({
            'PROGRESS': None, 'GOOD_PASSPHRASE': None, 'NODATA': None,
            'KEY_NOT_CREATED': self._key_not_created,
            'KEY_CREATED': self._key_created
        })

    def handle(self):
        super(GenKeyResult, self).handle()
        if not self.fingerprint:
            raise GeneralError(self.err)

    def _key_not_created(self, code, value):
        raise GeneralError(self.err)

    def _key_created(self, code, value):
        self.type, self.fingerprint = value.split()[:2]


class SignResult (Result):

    TYPE_DETACHED = 'D'
    TYPE_CLEARTEXT = 'C'
    TYPE_STANDARD = 'S'

    def __init__(self):
        super(SignResult, self).__init__()
        self.type = None
        self.pubkey_algorithm = None
        self.hash_algorithm = None
        self.cls = None
        self.timestamp = None
        self.fingerprint = None
        self.signer = None
        self.processors.update({
            'NEED_PASSPHRASE': None, 'GOOD_PASSPHRASE': None,
            'BEGIN_SIGNING': None, 'CARDCTRL': None, 'KEYEXPIRED': None,
            'SIGEXPIRED': None, 'KEYREVOKED': None, 'SC_OP_SUCCESS': None,
            'USERID_HINT': self._userid_hint,
            'SIG_CREATED': self._sig_created,
        })

    def handle(self):
        super(SignResult, self).handle()
        if not self.data:
            raise GeneralError(self.err)

    def _userid_hint(self, code, value):
        _, self.signer = value.split(None, 1)

    def _sig_created(self, code, value):
        self.type, self.pubkey_algorithm, self.hash_algorithm, self.cls, self.timestamp, self.fingerprint = value.split()
        self.pubkey_algorithm = to_int(self.pubkey_algorithm)
        self.hash_algorithm = to_int(self.hash_algorithm)
        self.timestamp = to_timestamp(self.timestamp)
        self.type = self.type.upper()[:1]


class VerifyResult (Result):

    STATE_OK = 'OK'
    STATE_SIG_EXPIRED = 'EXPSIG'
    STATE_KEY_REVOKED = 'REVKEYSIG'
    STATE_KEY_EXPIRED = 'EXPKEYSIG'

    def __init__(self):
        super(VerifyResult, self).__init__()
        self.valid = False
        self.state = self.STATE_OK
        self.fingerprint = None
        self.timestamp = None
        self.expire_timestamp = None
        self.id = None
        self.key_id = None
        self.signer = None
        self.processors.update({
            'RSA_OR_IDEA': None, 'IMPORT_RES': None, 'PLAINTEXT': None,
            'PLAINTEXT_LENGTH': None, 'POLICY_URL': None, 'DECRYPTION_INFO': None,
            'DECRYPTION_OKAY': None, 'FILE_START': None, 'FILE_ERROR': None,
            'FILE_DONE': None, 'PKA_TRUST_GOOD': None, 'PKA_TRUST_BAD': None,
            'BADMDC': None, 'GOODMDC': None, 'TRUST_UNDEFINED': None,
            'TRUST_NEVER': None, 'TRUST_MARGINAL': None, 'TRUST_FULLY': None,
            'TRUST_ULTIMATE': None, 'KEYEXPIRED': None, 'SIGEXPIRED': None,
            'KEYREVOKED': None,

            'EXPSIG': self._set_state,
            'EXPKEYSIG': self._set_state,
            'REVKEYSIG': self._set_state,
            'BADSIG': self._badsig,
            'GOODSIG': self._goodsig,
            'VALIDSIG': self._validsig,
            'ERRSIG': self._errsig,
            'SIG_ID': self._sig_id
        })

    def __nonzero__(self):
        return self.valid

    __bool__ = __nonzero__

    def _set_state(self, code, value):
        self.valid = False
        self.state = code
        self.key_id, self.signer = value.split(None, 1)

    def _badsig(self, code, value):
        self.valid = False
        self.key_id, self.signer = value.split(None, 1)

    def _goodsig(self, code, value):
        self.valid = True
        self.key_id, self.signer = value.split(None, 1)

    def _validsig(self, code, value):
        # This status indicates that the signature is good. This is the same
        # as GOODSIG but has the fingerprint as the argument. Both status
        # lines are emitted for a good signature.
        self.fingerprint, _, timestamp, expire_timestamp = value.split(None)[:4]
        self.timestamp = to_timestamp(timestamp)
        self.expire_timestamp = to_timestamp(expire_timestamp)
        # FIXME: читать поля  <sig-version> <reserved> <pubkey-algo>
        # <hash-algo> <sig-class>

    def _errsig(self, code, value):
        self.valid = False
        raw = value.split()
        if raw[5] == '4':
            raise AlgorithmError('Unsupported algorithm', self.err)
        if raw[5] == '9':
            raise GpgKeyError('Missing public key %s' % raw[0], self.err)
        raise GeneralError(self.err)

    def _sig_id(self, code, value):
        self.id = value.split()[0]


class EncryptResult (VerifyResult):

    def __init__(self):
        super(EncryptResult, self).__init__()
        del self.state
        del self.timestamp
        del self.expire_timestamp
        del self.id
        del self.key_id
        del self.fingerprint
        self.key_expired = False
        self.signature_expired = False
        self.processors.update({
            'SC_OP_SUCCESS': None, 'CARDCTRL': None, 'ENC_TO': None,
            'ERROR': None, 'USERID_HINT': None, 'BEGIN_SIGNING': None,
            'NEED_PASSPHRASE': None, 'NEED_PASSPHRASE_SYM': None, 'GOOD_PASSPHRASE': None,
            'BEGIN_DECRYPTION': None, 'END_DECRYPTION': None, 'DECRYPTION_OKAY': None,
            'BEGIN_ENCRYPTION': None, 'END_ENCRYPTION': None,
            'SIG_CREATED': None, 'DECRYPTION_KEY': None, 'DECRYPTION_COMPLIANCE_MODE': None,
            'VERIFICATION_COMPLIANCE_MODE': None,

            'KEY_NOT_CREATED': self._key_not_created,
            'KEYEXPIRED': self._key_expired,
            'SIGEXPIRED': self._sig_expired,
            'USERID_HINT': self._userid_hint
        })

    def handle(self):
        super(EncryptResult, self).handle()
        if not self.data:
            raise GeneralError(self.err)

    def _key_not_created(self, code, value):
        raise GeneralError(self.err)

    def _key_expired(self, code, value):
        self.key_expired = True

    def _sig_expired(self, code, value):
        self.signature_expired = True

    def _userid_hint(self, code, value):
        _, self.signer = value.split(None, 1)


class DecryptResult (EncryptResult):

    def handle(self):
        super(DecryptResult, self).handle()
        self.valid = bool(self.data)


class VersionResult (object):

    LINE_START = 'gpg (GnuPG) '

    def __init__(self):
        self.err = None
        self.data = None

    def handle(self):
        line = self.data.strip().split('\n')[0]
        if not line.startswith(self.LINE_START):
            raise GeneralError('gpg: Cannot get GnuPG version')
        self.version = tuple(int(n) for n in line[len(self.LINE_START):].split('.')[:2])


class GnuPG (object):

    default_key_params = {
        'Key-Type': 'RSA',
        'Key-Length': 1024,
        'Name-Real': 'Autogenerated key',
        'Name-Comment': 'Generated by regnupg',
        'Name-Email': '%s@%s' % (os.environ.get('LOGNAME', os.environ.get('USERNAME', 'user')).replace(' ', '_'), socket.gethostname())
    }

    def __init__(self, executable='gpg', homedir=None, use_agent=False):
        self.executable = executable
        self.homedir = homedir
        self.use_agent = use_agent
        self.encoding = locale.getpreferredencoding()
        if self.encoding is None:
            # This happens on Jython!
            self.encoding = sys.stdin.encoding
        self.version = None

    def create_stream(self, data):
        if (_py3k and isinstance(data, str)) or (not _py3k and type(data) != str):
            data = data.encode(self.encoding)
        return _BinaryStream(data)

    def execute(self, result, args, passphrase=None, input_=None, binary=False):

        def read_stderr(stderr):
            '''read and parse stderr'''
            result.err = []
            result.status = []
            while True:
                line = stderr.readline()
                if not line:
                    break
                line = line.rstrip()
                log.debug('GnuPG.execute(): <<< %s', line)
                if line.startswith('[GNUPG:]'):
                    line = line[9:]
                    try:
                        status, value = line.split(None, 1)
                    except ValueError:
                        status, value = line, ''
                    result.status.append((status, value))
                else:
                    result.err.append(line)

        def read_stdout(stdout):
            '''read stdout'''
            chunks = []
            while True:
                chunk = stdout.read(2048)
                if not chunk:
                    break
                chunks.append(chunk)
            result.data = (b'' if _py3k else '').join(
                chunks).decode(self.encoding)

        def copy_stream(source, target, chunk_size=1024):
            '''Copy one stream to another'''
            log.debug('copy_stream()')
            if not source:
                return
            sent = 0
            while True:
                data = source.read(chunk_size)
                if not data:
                    break
                if _py3k:
                    if binary and isinstance(data, str):
                        data = data.encode(self.encoding)
                    elif not binary and isinstance(data, bytes):
                        data = data.decode(self.encoding)
                log.debug('copy_stream(): sending chunk from pos %d', sent)
                try:
                    target.write(data)
                except UnicodeError:
                    if not _py3k and type(data) == str:
                        target.write(data.decode(self.encoding))
                    else:
                        target.write(data.encode(self.encoding))
                except:
                    # Broken pipes
                    log.exception('copy_stream(): error sending data')
                    break
                sent += len(data)
            try:
                target.close()
            except IOError:
                log.warning('copy_stream(): exception occurred while closing, ignored', exc_info=1)
            log.debug('copy_stream(): closed output, %d bytes sent', sent)

        def detach(func, *args):
            thread = threading.Thread(target=func, args=args)
            thread.setDaemon(True)
            thread.start()
            return thread

        if not self.version and args != ('--version',):
            self.version = self.execute(VersionResult(), ('--version',)).version

        cmd = [self.executable, '--status-fd', '2', '--no-tty',
               '--lock-multiple', '--no-permission-warning']
        if self.homedir is not None:
            cmd += ('--homedir', self.homedir)
        if passphrase is not None:
            if '--batch' not in args:
                cmd.append('--batch')
            cmd += ('--passphrase-fd', '0')
            if self.version >= (2, 1):
                cmd += ('--pinentry-mode', 'loopback')
        if self.use_agent:
            cmd.append('--use-agent')
        cmd.extend(args)

        log.debug('GnuPG.execute(): >>> %s', ' '.join(cmd))

        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **_popen_kwargs)

        stdin = proc.stdin if binary else codecs.getwriter(self.encoding)(proc.stdin)
        stderr = codecs.getreader(self.encoding)(proc.stderr)

        if passphrase is not None:
            # Пишем пароль в stdin
            if binary:
                passphrase = passphrase.encode(self.encoding)
            stdin.write(passphrase)
            stdin.write(b'\n' if _py3k and binary else '\n')
            log.debug('GnuPG.execute(): Wrote passphrase %r' % passphrase)

        # Запускаем поток перекачки данных из input_ в stdin
        in_writer = detach(copy_stream, input_, stdin)
        # Запускаем поток чтения и разбора stderr
        err_reader = detach(read_stderr, stderr)
        # Запускаем поток чтения выходных данных
        out_reader = detach(read_stdout, proc.stdout)

        # Ожидаем завершения работы писалок/читалок
        out_reader.join()
        err_reader.join()
        in_writer.join()

        # Ждем завершения процесса
        proc.wait()

        # Закроем поток записи, если все еще открыт
        try:
            stdin.close()
        except IOError:
            pass
        # И все остальное
        proc.stdout.close()
        stderr.close()

        # Обработаем результат
        result.handle()
        return result

    def import_keys_file(self, keydata_file):
        '''
        Import/merge keys from file. This adds the given keys to the keyring.

        :param keydata_file: File-like object with keydata
        :rtype: ImportResult
        '''
        return self.execute(ImportResult(), ('--import',), None, keydata_file, True)

    def import_keys(self, keydata):
        '''
        Import/merge keys from string. This adds the given keys to the keyring.

        :param keydata: Keydata string or bytes
        :rtype: ImportResult
        '''
        return self.import_keys_file(self.create_stream(keydata))

    def recv_keys(self, keyserver, keys):
        '''
        Import the keys with the given key IDs from a HKP keyserver.

        :param keyserver: Keyserver name. The format of the name is a URI: ``scheme:[//]keyservername[:port]``.
            The scheme is the type of keyserver:"hkp" for the HTTP (or compatible) keyservers, "ldap" for the
            NAI LDAP keyserver, or "mailto" for the Graff email keyserver. Note that your particular installation
            of GnuPG may have other keyserver types available as well. Keyserver schemes are case-insensitive.
        :param keys: Single key ID or list of mutiple IDs
        :rtype: ImportResult
        '''
        return self.execute(
            ImportResult(),
            ['--keyserver', keyserver, '--recv-keys'] + list(make_list(keys))
        )

    def list_keys(self, secret=False):
        '''
        List keys from the public or secret keyrings.

        :param secret: List secret keys
        :rtype: ListResult
        '''
        return self.execute(
            ListResult(),
            (
                '--list-secret-keys' if secret else '--list-keys',
                '--fixed-list-mode',
                '--fingerprint',
                '--with-colons'
            )
        )

    def export_keys(self, keys=None, secret=False, passphrase=None, binary=False):
        '''
        Export keys

        :param keys: Single key ID or list of mutiple IDs. If None export all of the keys.
        :param secret: Export secret keys
        :param passphrase: Secret key password, you need this if secret=true
        :param binary: If false, create ASCII armored output
        :rtype: ExportResult
        '''
        args = [] if binary else ['--armor']
        if secret:
            args += ('--batch', '--export-secret-keys')
        else:
            args.append('--export')
        if keys:
            args += make_list(keys)
        return self.execute(ExportResult(), args, passphrase or '' if secret else None)

    def delete_keys(self, keys, secret=False):
        '''
        Remove keys from the public or secret keyrings.

        :param keys: Single key ID or list of mutiple IDs
        :param secret: Delete secret keys
        :rtype: DeleteResult
        '''
        return self.execute(
            DeleteResult(),
            ['--batch', '--yes', '--delete-secret-key' if secret else '--delete-key'] + list(make_list(keys))
        )

    def key_exists(self, key, secret=False):
        '''
        Check is given key exists.

        :param key: Key ID
        :param secret: Check secret key
        :rtype: bool
        '''
        if len(key) < 8:
            return False
        key = key.upper()
        res = self.list_keys(secret)
        for fingerprint in res.keys:
            if fingerprint.endswith(key):
                return True
        return False

    def gen_key_input(self, key_params={}):
        '''
        Generate --gen-key input per gpg doc/DETAILS.

        :param key_params: Key parameters
        :rtype: str
        :return: Control input for :func:`regnupg.gen_key`
        '''
        params = self.default_key_params.copy()
        params.update(key_params)
        result = ['Key-Type: %s' % params.pop('Key-Type')]
        result += ('%s: %s' % (param, value) for param, value in params.items())
        result.append('%commit\n')
        return '\n'.join(result)

    def gen_key(self, key_input):
        '''
        Generate a new key pair; you might use :func:`regnupg.gen_key_input` to create the control input.

        :param input: GnuPG key generation control input
        :rtype: GenKeyResult
        '''
        return self.execute(GenKeyResult(), ('--gen-key', '--batch'), None, self.create_stream(key_input))

    def sign_file(self, message_file, key_id=None, passphrase=None,
                  clearsign=True, detach=False, binary=False):
        '''
        Make a signature.

        :param message_file: File-like object for sign
        :param key_id: Key for signing, default will be used if null
        :param passphrase: Key password
        :param clearsign: Make a clear text signature
        :param detach: Make a detached signature
        :param binary: If false, create ASCII armored output
        :rtype: SignResult
        '''
        args = ['-s' if binary else '-sa']
        if detach:
            args.append('--detach-sign')
        if clearsign:
            args.append('--clearsign')
        if key_id:
            #args += ('--default-key', key_id)
            args += ('--local-user', key_id)
        return self.execute(SignResult(), args, passphrase, message_file, True)

    def sign(self, message, *args, **kwargs):
        '''
        Make a signature.

        :param message: Message to sign
        :param key_id: Key for signing, default will be used if null
        :param passphrase: Key password
        :param clearsign: Make a clear text signature
        :param detach: Make a detached signature
        :param binary: If false, create ASCII armored output
        :rtype: SignResult
        '''
        return self.sign_file(self.create_stream(message), *args, **kwargs)

    def verify_file(self, sign_file, data_filename=None):
        '''
        Verify given signature

        :param sign_file: File-like object containing sign
        :param data_filename: Assume signature is detached when not null
        :rtype: VerifyResult
        '''
        if data_filename is None:
            return self.execute(VerifyResult(), ('--verify',), None, sign_file)
        # Подпись для detached пишем в отдельный файл
        sign_filename, sign_fd = tempfile.mkstemp(prefix=__name__)
        os.write(sign_fd, sign_file.read())
        os.close(sign_fd)
        try:
            result = self.execute(
                VerifyResult(), ('--verify', sign_filename, data_filename))
        finally:
            os.remove(sign_filename)
        return result

    def verify(self, sign, *args, **kwargs):
        '''
        Verify given signature

        :param sign: Sign data
        :param data_filename: Assume signature is detached when not null
        :rtype: VerifyResult
        '''
        return self.verify_file(self.create_stream(sign), *args, **kwargs)

    def encrypt_file(self, data_file, recipients, sign_key=None, passphrase=None,
                     always_trust=False, output_filename=None, binary=False, symmetric=False):
        '''
        Sign/Encrypt file

        :param data_file: File-like object containing data
        :param recipients: Single key ID or list of mutiple IDs. Will be ignored if symmetric
        :param sign_key: Key for signing data before encryption. No sign will be made when not given
        :param passphrase: Password for key or symmetric cipher
        :param always_trust: Skip key validation and assume that used keys are always fully trusted
        :param output_filename: Encrypted data will be written to file when not None
        :param binary: If false, create ASCII armored output
        :param symmetric: Encrypt with symmetric cipher only
        :rtype: EncryptResult
        '''
        if symmetric:
            args = ['--symmetric']
        else:
            args = ['--encrypt']
            for recipient in make_list(recipients):
                args += ('--recipient', recipient)
        if not binary:
            args.append('--armor')
        if output_filename:
            if os.path.exists(output_filename):
                # to avoid overwrite confirmation message
                os.remove(output_filename)
            args += ('--output', output_filename)
        if sign_key:
            args += ('--sign', '--local-user', sign_key)
        if always_trust:
            #args.append ('--always-trust')
            args += ('--trust-model', 'always')
        return self.execute(EncryptResult(), args, passphrase if passphrase is not None else '', data_file, True)

    def encrypt(self, data, *args, **kwargs):
        '''
        Sign/Encrypt

        :param data: Data to encrypt
        :param recipients: Single key ID or list of mutiple IDs. Will be ignored if symmetric
        :param sign_key: Key for signing data before encryption. No sign will be made when not given
        :param passphrase: Password for key or symmetric cipher
        :param always_trust: Skip key validation and assume that used keys are always fully trusted
        :param output_filename: Encrypted data will be written to this file when not None
        :param binary: If false, create ASCII armored output
        :param symmetric: Encrypt with symmetric cipher only
        :rtype: EncryptResult
        '''
        return self.encrypt_file(self.create_stream(data), *args, **kwargs)

    def decrypt_file(self, encrypted_file, passphrase, signer_key=None,
                     always_trust=False, output_filename=None):
        '''
        Decrypt/verify file

        :param encrypted_file: File-like object containing encrypted data
        :param passphrase: Passphrase
        :param signer_key: Signer key ID. Sign will not be verifyed when None
        :param always_trust: Skip key validation and assume that used keys are always fully trusted
        :param output_filename: Decrypted data will be written to this file when not None
        :rtype: EncryptResult
        '''
        args = ['--decrypt']
        if signer_key:
            args += ('-u', signer_key)
        if output_filename:
            if os.path.exists(output_filename):
                # to avoid overwrite confirmation message
                os.remove(output_filename)
            args += ('--output', output_filename)
        if always_trust:
            #args.append ('--always-trust')
            args += ('--trust-model', 'always')
        return self.execute(DecryptResult(), args, passphrase, encrypted_file, True)

    def decrypt(self, encrypted_data, *args, **kwargs):
        '''
        Decrypt/verify

        :param encrypted_data: Encrypted data
        :param passphrase: Passphrase
        :param signer_key: Signer key ID. Sign will not be verifyed when None
        :param always_trust: Skip key validation and assume that used keys are always fully trusted
        :param output_filename: Decrypted data will be written to this file when not None
        :rtype: EncryptResult
        '''
        return self.decrypt_file(self.create_stream(encrypted_data), *args, **kwargs)


