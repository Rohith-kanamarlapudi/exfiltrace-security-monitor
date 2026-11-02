"""Local-only recovery API; explicit header required for mutations."""
from flask import Blueprint, current_app, jsonify, request
from .jobs import RecoveryJobs

bp = Blueprint('usb_recovery', __name__, url_prefix='/api/usb/recovery')


def register(app, service):
    app.config['USB_RECOVERY'] = RecoveryJobs(service)
    app.register_blueprint(bp)


@bp.before_request
def guard():
    from ...api import _local_simulation_request
    if not _local_simulation_request():
        return jsonify(error='Recovery requires a local backend connection and local page origin.'), 403
    if request.method not in ('GET', 'OPTIONS') and request.headers.get('X-ExfilTrace-Recovery') != '1':
        return jsonify(error='Explicit recovery request header required.'), 403


@bp.after_request
def cors(response):
    from ...api import _local_simulation_request
    if _local_simulation_request():
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', request.host_url.rstrip('/'))
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-ExfilTrace-Recovery'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Vary'] = 'Origin'
    return response


@bp.get('')
def status():
    return jsonify(data=current_app.config['USB_RECOVERY'].status(), source='live')


@bp.post('/jobs')
@bp.post('/jobs/<job_id>')
def mutate(job_id=None):
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error='Expected a JSON object.'), 400
    manager = current_app.config['USB_RECOVERY']
    try:
        data = manager.action(job_id, body) if job_id else manager.start(body)
        return jsonify(data=data, source='live'), 202
    except ValueError as exc:
        return jsonify(error=str(exc)), 409
