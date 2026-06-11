import json, os, queue, threading, time
from flask import Flask, Response, jsonify, render_template, request, send_from_directory
from main import run_crypto_search, rotator

app = Flask(__name__, template_folder='templates')

# ---------------------------------------------------------------------------
# In-memory job store (single concurrent job)
# ---------------------------------------------------------------------------
_job = {
    'running': False,
    'queue': queue.Queue(),
    'findings': [],
    'urls_count': 0,
    'error': None,
}


def _run_job(keyword, rate_limit):
    _job['running'] = True
    _job['findings'] = []
    _job['urls_count'] = 0
    _job['error'] = None

    def on_progress(event):
        _job['queue'].put(event)
        if event.get('level') == 'done':
            _job['findings_count'] = event.get('findings_count', 0)
            _job['urls_count'] = event.get('urls_count', 0)

    try:
        urls, findings = run_crypto_search(
            keyword=keyword or None,
            output_dir='./crypto_output',
            rate_limit=rate_limit,
            progress_callback=on_progress
        )
        _job['findings'] = findings
        _job['urls_count'] = len(urls)
    except Exception as e:
        _job['error'] = str(e)
        _job['queue'].put({'level': 'error', 'message': f'Fatal error: {e}'})
        _job['queue'].put({'level': 'done', 'message': 'Search stopped due to error',
                           'findings_count': 0, 'urls_count': 0})
    finally:
        _job['running'] = False


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/start', methods=['POST'])
def start_search():
    if _job['running']:
        return jsonify({'ok': False, 'error': 'A search is already running.'}), 409

    data = request.get_json() or {}
    keyword = (data.get('keyword') or '').strip()
    rate_limit = float(data.get('rate_limit', 5.0))

    # Clear queue
    while not _job['queue'].empty():
        try:
            _job['queue'].get_nowait()
        except queue.Empty:
            break

    t = threading.Thread(target=_run_job, args=(keyword, rate_limit), daemon=True)
    t.start()
    return jsonify({'ok': True})


@app.route('/api/stream')
def stream():
    def event_gen():
        # Send initial heartbeat
        yield f"data: {json.dumps({'level': 'info', 'message': 'Connected. Waiting for search to start…'})}\n\n"
        while True:
            try:
                event = _job['queue'].get(timeout=25)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get('level') == 'done':
                    break
            except queue.Empty:
                yield ": heartbeat\n\n"

    return Response(event_gen(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/status')
def status():
    return jsonify({
        'running': _job['running'],
        'findings_count': len(_job.get('findings', [])),
        'urls_count': _job.get('urls_count', 0),
        'error': _job.get('error'),
        'tokens': rotator.status(),
        'token_count': rotator.count(),
    })


@app.route('/api/findings')
def findings():
    return jsonify(_job.get('findings', []))


@app.route('/api/tokens', methods=['GET'])
def get_tokens():
    return jsonify({'tokens': rotator.status(), 'count': rotator.count()})


@app.route('/api/tokens/reload', methods=['POST'])
def reload_tokens():
    rotator.reload()
    return jsonify({'ok': True, 'count': rotator.count(), 'tokens': rotator.status()})


@app.route('/download/<path:filename>')
def download(filename):
    return send_from_directory('crypto_output', filename, as_attachment=True)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
