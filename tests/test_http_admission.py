"""Admission and upload deadlines precede authentication, routing, and scoring."""

import asyncio
import http.client
import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import time

import anyio
import pytest

from lurescope.http_boundary import RequestBodyLimit, configured_admission_limits

SCOPE = {'type': 'http', 'headers': []}


def chunk(body=b'', more=False):
    return {'type': 'http.request', 'body': body, 'more_body': more}


def test_default_seventeenth_request_never_reads_or_enters_application():
    async def scenario():
        entered, read, sent = [], [], []
        release = asyncio.Event()
        started = asyncio.Queue()

        async def downstream(scope, receive, send):
            entered.append(scope['number'])
            started.put_nowait(True)
            await release.wait()

        async def receive():
            read.append(True)
            return chunk()

        async def send(message):
            sent.append(message)

        boundary = RequestBodyLimit(downstream)
        tasks = []
        try:
            for number in range(16):
                tasks.append(asyncio.create_task(
                    boundary({**SCOPE, 'number': number}, receive, send)))
                await asyncio.wait_for(started.get(), 1)
            await asyncio.wait_for(boundary({**SCOPE, 'number': 16}, receive, send), 1)
            assert entered == list(range(16))
            assert len(read) == 16
            assert sent[0]['status'] == 503
            assert json.loads(sent[1]['body']) == {'detail': 'request admission is busy'}
        finally:
            release.set()
            await asyncio.gather(*tasks)

    asyncio.run(scenario())


@pytest.mark.parametrize('stage', ['upload', 'route', 'response'])
@pytest.mark.parametrize('cancel', [False, True])
def test_slot_is_held_until_asgi_completion_and_released_on_failure(stage, cancel):
    async def scenario():
        started, release = asyncio.Event(), asyncio.Event()
        sent, calls = [], []
        failing = True

        async def pause(where):
            if failing and stage == where:
                started.set()
                await release.wait()
                raise RuntimeError('PRIVATE_SYNTHETIC_FAILURE')

        async def receive():
            await pause('upload')
            return chunk()

        async def send(message):
            await pause('response')
            sent.append(message)

        async def downstream(scope, receive, send):
            calls.append(True)
            await receive()
            await pause('route')
            await send({'type': 'http.response.start', 'status': 200, 'headers': []})
            await send({'type': 'http.response.body', 'body': b'OK'})

        boundary = RequestBodyLimit(downstream, max_in_flight=1)
        first = asyncio.create_task(boundary(SCOPE, receive, send))
        try:
            await asyncio.wait_for(started.wait(), 1)
            rejected = []

            async def reject_send(message):
                rejected.append(message)

            async def forbidden_receive():
                pytest.fail('saturated request read a body')

            await boundary(SCOPE, forbidden_receive, reject_send)
            assert rejected[0]['status'] == 503
            assert dict(rejected[0]['headers'])[b'retry-after'] == b'1'
            if cancel:
                first.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await first
            else:
                release.set()
                with pytest.raises(RuntimeError, match='PRIVATE_SYNTHETIC'):
                    await first
        finally:
            if not first.done():
                first.cancel()
                await asyncio.gather(first, return_exceptions=True)
        failing = False
        sent.clear()
        await boundary(SCOPE, receive, send)
        assert sent[0]['status'] == 200

    asyncio.run(scenario())


@pytest.mark.parametrize('style', ['trickle', 'empty_immediate', 'blocking_final'])
def test_deadline_is_total_and_does_not_restart_for_progress(style):
    async def scenario():
        calls, sent = [], []

        async def receive():
            calls.append(True)
            if style == 'trickle':
                await asyncio.sleep(.01)
                return chunk(b' ', True)
            if style == 'blocking_final':
                time.sleep(.06)  # Synthetic non-cooperative server: check elapsed on return.
                return chunk(b'{}')
            return chunk(b'', True)

        async def downstream(*args):
            pytest.fail('expired upload reached a route')

        async def send(message):
            sent.append(message)

        boundary = RequestBodyLimit(downstream, body_timeout_seconds=.04)
        await asyncio.wait_for(boundary(SCOPE, receive, send), 1)
        assert sent[0]['status'] == 408
        assert calls

    asyncio.run(scenario())


def test_body_deadline_does_not_cancel_a_running_route():
    async def scenario():
        sent = []

        async def receive():
            return chunk(b'{}')

        async def downstream(scope, receive, send):
            assert (await receive())['body'] == b'{}'
            await asyncio.sleep(.15)
            await send({'type': 'http.response.start', 'status': 200, 'headers': []})

        async def send(message):
            sent.append(message)

        await RequestBodyLimit(downstream, body_timeout_seconds=.1)(SCOPE, receive, send)
        assert sent[0]['status'] == 200

    asyncio.run(scenario())


@pytest.mark.parametrize('failure', ['disconnect', 'late_disconnect', 'invalid_json',
                                    'overflow', 'timeout', 'stream_error', 'transport_timeout'])
def test_admission_recovers_after_upload_rejection(failure):
    async def scenario():
        sent, entered = [], []

        async def bad_receive():
            if failure in {'disconnect', 'late_disconnect'}:
                if failure == 'late_disconnect':
                    time.sleep(.04)
                return {'type': 'http.disconnect'}
            if failure == 'invalid_json':
                return chunk(b'{bad')
            if failure == 'overflow':
                return chunk(b' ' * 9)
            if failure == 'stream_error':
                return {'type': 'http.request', 'body': 'not-bytes'}
            if failure == 'transport_timeout':
                raise TimeoutError('upstream timeout, not local deadline')
            await asyncio.Event().wait()

        async def downstream(scope, receive, send):
            entered.append(await receive())

        async def send(message):
            sent.append(message)

        boundary = RequestBodyLimit(downstream, 8, max_in_flight=1, body_timeout_seconds=.02)
        if failure == 'transport_timeout':
            with pytest.raises(TimeoutError, match='upstream'):
                await boundary(SCOPE, bad_receive, send)
        else:
            await boundary(SCOPE, bad_receive, send)
        assert not entered
        if failure in {'disconnect', 'late_disconnect', 'transport_timeout'}:
            assert not sent
        else:
            assert len(sent) == 2

        async def good_receive():
            return chunk(b'{}')

        await boundary(SCOPE, good_receive, send)
        assert entered == [chunk(b'{}')]

    asyncio.run(scenario())


@pytest.mark.parametrize('kind,bad', [
    ('max_in_flight', True), ('max_in_flight', False), ('max_in_flight', 0),
    ('max_in_flight', 257), ('max_in_flight', 1.0), ('max_in_flight', '1'),
    ('body_timeout_seconds', True), ('body_timeout_seconds', 0),
    ('body_timeout_seconds', -1), ('body_timeout_seconds', 301),
    ('body_timeout_seconds', float('nan')), ('body_timeout_seconds', float('inf')),
    ('body_timeout_seconds', '1'),
])
def test_limits_require_bounded_finite_values(kind, bad):
    with pytest.raises(ValueError, match=kind):
        RequestBodyLimit(None, **{kind: bad})


@pytest.mark.parametrize('name,value', [
    ('LURESCOPE_HTTP_MAX_IN_FLIGHT', 'PRIVATE_INVALID'),
    ('LURESCOPE_HTTP_MAX_IN_FLIGHT', '0'),
    ('LURESCOPE_HTTP_MAX_IN_FLIGHT', '257'),
    ('LURESCOPE_HTTP_MAX_IN_FLIGHT', '9' * 65),
    ('LURESCOPE_HTTP_BODY_TIMEOUT_SECONDS', 'nan'),
    ('LURESCOPE_HTTP_BODY_TIMEOUT_SECONDS', 'inf'),
    ('LURESCOPE_HTTP_BODY_TIMEOUT_SECONDS', '0'),
    ('LURESCOPE_HTTP_BODY_TIMEOUT_SECONDS', '301'),
])
def test_environment_errors_are_redacted(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match='^invalid HTTP admission configuration$'):
        configured_admission_limits()


def test_environment_config_is_snapshotted_at_construction(monkeypatch):
    monkeypatch.setenv('LURESCOPE_HTTP_MAX_IN_FLIGHT', '2')
    monkeypatch.setenv('LURESCOPE_HTTP_BODY_TIMEOUT_SECONDS', '1.5')
    options = configured_admission_limits()
    assert options == {'max_in_flight': 2, 'body_timeout_seconds': 1.5}
    boundary = RequestBodyLimit(None, **options)
    monkeypatch.setenv('LURESCOPE_HTTP_BODY_TIMEOUT_SECONDS', '2.5')
    assert boundary.body_timeout_seconds == 1.5


@pytest.mark.parametrize('valid', [False, True])
def test_actual_application_startup_uses_and_validates_configuration(valid):
    result = subprocess.run([sys.executable, '-c',
        'import json; from lurescope.app import app; '
        'print(json.dumps(app.user_middleware[0].kwargs))'], capture_output=True, text=True,
        timeout=10, env={**os.environ,
                         'LURESCOPE_HTTP_MAX_IN_FLIGHT': '2' if valid else 'PRIVATE_BAD',
                         'LURESCOPE_HTTP_BODY_TIMEOUT_SECONDS': '1.5'})
    if valid:
        assert result.returncode == 0
        assert json.loads(result.stdout) == {'max_in_flight': 2, 'body_timeout_seconds': 1.5}
    else:
        assert result.returncode != 0
        assert 'invalid HTTP admission configuration' in result.stderr
        assert 'PRIVATE_BAD' not in result.stdout + result.stderr


def test_complete_body_is_delivered_once_then_disconnect_is_forwarded():
    async def scenario():
        incoming = iter([chunk(b'{', True), chunk(b'}'), {'type': 'http.disconnect'}])
        seen = []

        async def receive():
            return next(incoming)

        async def downstream(scope, receive, send):
            seen.extend([await receive(), await receive()])

        await RequestBodyLimit(downstream)(SCOPE, receive, None)
        assert seen == [chunk(b'{}'), {'type': 'http.disconnect'}]

    asyncio.run(scenario())


def test_outer_anyio_cancellation_is_not_an_upload_timeout():
    async def scenario():
        sent = []

        async def receive():
            await anyio.sleep_forever()

        async def forbidden(*args):
            pytest.fail('cancelled request entered route')

        async def send(message):
            sent.append(message)

        boundary = RequestBodyLimit(forbidden, max_in_flight=1, body_timeout_seconds=1)
        with anyio.move_on_after(.01) as outer:
            await boundary(SCOPE, receive, send)
        assert outer.cancelled_caught
        assert not sent
        assert boundary._slots.acquire(blocking=False)
        boundary._slots.release()

    anyio.run(scenario)


def test_partial_upload_deadline_does_not_enter_application():
    async def scenario():
        calls, sent = [], []

        async def receive():
            calls.append(True)
            if len(calls) == 1:
                return chunk(b'"partial', True)
            await asyncio.Event().wait()

        async def downstream(*args):
            pytest.fail('timed-out upload reached a route')

        async def send(message):
            sent.append(message)

        boundary = RequestBodyLimit(downstream, body_timeout_seconds=.03)
        await asyncio.wait_for(boundary(SCOPE, receive, send), 1)
        assert sent[0]['status'] == 408
        assert json.loads(sent[1]['body']) == {'detail': 'request body deadline exceeded'}

    asyncio.run(scenario())


def test_ambiguous_content_type_rejected_without_upload():
    async def scenario():
        sent = []

        async def forbidden(*args):
            pytest.fail('ambiguous content type consumed upload or entered route')

        async def send(message):
            sent.append(message)

        await RequestBodyLimit(forbidden)({**SCOPE, 'headers': [
            (b'content-type', b'application/json'), (b'Content-Type', b'application/json'),
        ]}, forbidden, send)
        assert sent[0]['status'] == 400

    asyncio.run(scenario())


@pytest.mark.parametrize('version', ['1.0', '1.1', '2', '3'])
def test_rejections_close_only_http1_connections(version):
    async def scenario():
        sent = []

        async def forbidden(*args):
            pytest.fail('duplicate encoding reached upload or route')

        async def send(message):
            sent.append(message)

        scope = {**SCOPE, 'http_version': version, 'headers': [
            (b'content-encoding', b'identity'), (b'Content-Encoding', b'identity'),
        ]}
        await RequestBodyLimit(forbidden)(scope, forbidden, send)
        assert sent[0]['status'] == 400
        headers = dict(sent[0]['headers'])
        assert headers[b'cache-control'] == b'no-store'
        assert (headers.get(b'connection') == b'close') == version.startswith('1.')

    asyncio.run(scenario())


@pytest.mark.parametrize('kind', ['lifespan', 'websocket'])
def test_non_http_scopes_bypass_http_admission(kind):
    async def scenario():
        entered = []

        async def downstream(scope, receive, send):
            entered.append(scope['type'])

        boundary = RequestBodyLimit(downstream, max_in_flight=1)
        with boundary._slots:
            await boundary({'type': kind}, None, None)
        assert entered == [kind]

    asyncio.run(scenario())


@pytest.mark.parametrize('loop', ['asyncio', 'uvloop'])
def test_real_uvicorn_recovers_after_partial_upload_and_saturation(loop, monkeypatch):
    import uvicorn

    from lurescope import security, service
    from lurescope.app import app

    if loop == 'uvloop' and importlib.util.find_spec('uvloop') is None:
        pytest.skip('uvloop not installed on this platform')
    monkeypatch.delenv('LURESCOPE_PUBLIC_MODE', raising=False)
    monkeypatch.delenv('LURESCOPE_API_KEY_SCRYPT', raising=False)
    monkeypatch.setattr(service, 'score', lambda *a, **kw: pytest.fail('upload reached scoring'))
    monkeypatch.setattr(security, '_derive_api_key',
                        lambda *a, **kw: pytest.fail('upload reached authentication'))
    reading = threading.Event()
    routed, failures = [], []

    async def downstream(scope, receive, send):
        routed.append(scope['path'])
        await app(scope, receive, send)

    boundary = RequestBodyLimit(downstream, max_in_flight=1, body_timeout_seconds=.5)

    async def observed(scope, receive, send):
        async def observed_receive():
            reading.set()
            return await receive()

        await boundary(scope, observed_receive, send)

    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(8)
        address = listener.getsockname()
        server = uvicorn.Server(uvicorn.Config(observed, loop=loop, http='h11', ws='none',
            lifespan='off', log_config=None, access_log=False, log_level='critical',
            timeout_graceful_shutdown=1))

        def run():
            try:
                server.run(sockets=[listener])
            except BaseException as exc:
                failures.append(exc)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 3
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(.01)
            assert server.started and not failures
            with socket.create_connection(address, timeout=2) as slow:
                slow.sendall(b'POST /score HTTP/1.1\r\nHost: local\r\nContent-Length: 80\r\n'
                             b'Content-Type: application/json\r\n\r\n{"text":"PRIVATE_PARTIAL')
                assert reading.wait(1)
                with socket.create_connection(address, timeout=2) as busy:
                    busy.sendall(b'GET /health HTTP/1.1\r\nHost: local\r\n\r\n')
                    response = http.client.HTTPResponse(busy)
                    response.begin()
                    assert response.status == 503
                    assert response.getheader('Retry-After') == '1'
                    assert response.getheader('Connection') == 'close'
                    assert json.loads(response.read()) == {'detail': 'request admission is busy'}
                    assert busy.recv(1) == b''
                response = http.client.HTTPResponse(slow)
                response.begin()
                assert response.status == 408
                assert json.loads(response.read()) == {'detail': 'request body deadline exceeded'}
                assert slow.recv(1) == b''
                assert routed == []
            with socket.create_connection(address, timeout=2) as healthy:
                healthy.sendall(b'GET /health HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n')
                response = http.client.HTTPResponse(healthy)
                response.begin()
                assert response.status == 200
                assert json.loads(response.read())['status'] == 'ok'
            assert routed == ['/health']
        finally:
            server.should_exit = True
            thread.join(4)
        assert not thread.is_alive() and not failures
