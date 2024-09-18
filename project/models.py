from flask_login import UserMixin
from. import db
from datetime import datetime as dt
from sqlalchemy import CheckConstraint


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False)
    flagged = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def get_id(self):
        return str(self.user_id)

class Sponsor(db.Model):
    __tablename__ = 'sponsor'
    sponsor_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    company = db.Column(db.String(100))
    industry = db.Column(db.String(100))
    budget = db.Column(db.Float)
    flagged = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref=db.backref('sponsor', uselist=False, lazy=True))

class Influencer(db.Model):
    __tablename__ = 'influencer'
    influencer_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    name = db.Column(db.String(100))
    niche = db.Column(db.String(100))
    followers = db.Column(db.Integer)
    user = db.relationship('User', backref=db.backref('influencer', uselist=False, lazy=True))


class Campaign(db.Model):
    __tablename__ = 'campaign'
    campaign_id = db.Column(db.Integer, primary_key=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('sponsor.sponsor_id'), nullable=False)
    name = db.Column(db.String(100))
    description = db.Column(db.String(500))
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    budget = db.Column(db.Float)
    visibility = db.Column(db.Boolean, default=True)
    flagged = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=dt.utcnow)
    sponsor = db.relationship('Sponsor', backref=db.backref('campaigns', lazy=True))

    __table_args__ = (
        CheckConstraint('budget >= 0', name='budget_non_negative'),
        CheckConstraint('end_date > start_date', name='end_date_after_start_date')
    )

    def __repr__(self):
        return f"Campaign(campaign_id={self.campaign_id}, campaign_name='{self.name}')"

class AdRequest(db.Model):
    __tablename__ = 'adrequest'
    ad_request_id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.campaign_id'), nullable=False)
    influencer_id = db.Column(db.Integer, db.ForeignKey('influencer.influencer_id'), nullable=False)
    messages = db.Column(db.String(500))
    requirements = db.Column(db.String(500))  
    payment_amount = db.Column(db.Float)
    status = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    campaign = db.relationship('Campaign', backref=db.backref('ad_requests', lazy=True))
    influencer = db.relationship('Influencer', backref=db.backref('ad_requests', lazy=True))



