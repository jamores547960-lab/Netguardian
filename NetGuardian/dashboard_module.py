from flask import Blueprint, render_template
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

dashboard_bp = Blueprint('dashboard', __name__)
db = SQLAlchemy()

# Database Model: Live Honeypot Events
class HoneypotEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    attack_type = db.Column(db.String(100), nullable=False)
    activity = db.Column(db.String(255), nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)  # Critical, High, Medium, Low
    status = db.Column(db.String(20), default="Detected")

# Database Model: Detection Types Monitored
class DetectionType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    icon = db.Column(db.String(50), default="fa-shield-cat")
    status = db.Column(db.String(20), default="Monitoring")

@dashboard_bp.route('/dashboard')
def render_dashboard():
    # Fetch events and detection types from SQLite database
    events = HoneypotEvent.query.order_by(HoneypotEvent.timestamp.desc()).all()
    detections = DetectionType.query.all()

    # Dynamic KPI metric calculations
    total_events = len(events)
    unique_ips = len(set(e.ip_address for e in events))
    high_risk_events = sum(1 for e in events if e.risk_level in ['High', 'Critical'])
    critical_events = sum(1 for e in events if e.risk_level == 'Critical')

    return render_template(
        'dashboard.html',
        events=events,
        detections=detections,
        total_events=total_events,
        unique_ips=unique_ips,
        high_risk_events=high_risk_events,
        critical_events=critical_events
    )