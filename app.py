import json, os, queue, threading, time
from flask import Flask, Response, jsonify, render_template, request, send_from_directory
from main import run_crypto_search, rotator

app = Flask(__name__, template_folder='templates')

# ---------------------------------------------------------------------------
# Job store
# ---------------------------------------------------------------------------
_job = {
    'running':      False,
    'queue':        queue.Queue(),
    'findings':     [],
    'urls_count':   0,
    'quality_pct':  0,
    'high_quality': 0,
    'error':        None,
}


def _run_job(keyword, rate_limit, min_score):
    _job['running']      = True
    _job['findings']     = []
    _job['urls_count']   = 0
    _job['quality_pct']  = 0
    _job['high_quality'] = 0
    _job['error']        = None

    def on_progress(event):
        _job['queue'].put(event)
        if event.get('level') == 'done':
            _job['quality_pct']  = event.get('quality_pct', 0)
            _job['high_quality'] = event.get('high_quality_count', 0)
            _job['urls_count']   = event.get('urls_count', 0)

    try:
        _, findings = run_crypto_search(
            keyword=keyword or None,
            output_dir='./crypto_output',
            rate_limit=rate_limit,
            min_score=min_score,
            progress_callback=on_progress,
        )
        _job['findings'] = findings
    except Exception as e:
        _job['error'] = str(e)
        _job['queue'].put({'level': 'error', 'message': f'Fatal: {e}'})
        _job['queue'].put({'level': 'done', 'message': 'Stopped',
                           'findings_count': 0, 'urls_count': 0,
                           'high_quality_count': 0, 'quality_pct': 0})
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
        return jsonify({'ok': False, 'error': 'Search already running.'}), 409
    data      = request.get_json() or {}
    keyword   = (data.get('keyword') or '').strip()
    rate_limit = float(data.get('rate_limit', 5.0))
    min_score  = int(data.get('min_score', 65))

    while not _job['queue'].empty():
        try: _job['queue'].get_nowait()
        except queue.Empty: break

    threading.Thread(target=_run_job,
                     args=(keyword, rate_limit, min_score),
                     daemon=True).start()
    return jsonify({'ok': True})


@app.route('/api/stream')
def stream():
    def gen():
        yield f"data: {json.dumps({'level':'info','message':'Connected — waiting for search…'})}\n\n"
        while True:
            try:
                ev = _job['queue'].get(timeout=25)
                yield f"data: {json.dumps(ev)}\n\n"
                if ev.get('level') == 'done':
                    break
            except queue.Empty:
                yield ": heartbeat\n\n"
    return Response(gen(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/status')
def status():
    findings = _job.get('findings', [])
    return jsonify({
        'running':       _job['running'],
        'findings_count': len(findings),
        'urls_count':    _job['urls_count'],
        'quality_pct':   _job['quality_pct'],
        'high_quality':  _job['high_quality'],
        'error':         _job['error'],
        'tokens':        rotator.status(),
        'token_count':   rotator.count(),
    })


@app.route('/api/findings')
def findings():
    return jsonify(_job.get('findings', []))


@app.route('/api/tokens/reload', methods=['POST'])
def reload_tokens():
    rotator.reload()
    return jsonify({'ok': True, 'count': rotator.count(), 'tokens': rotator.status()})


@app.route('/download/<path:filename>')
def download(filename):
    return send_from_directory('crypto_output', filename, as_attachment=True)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
