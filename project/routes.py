from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, jsonify,send_file
from . import db
from sqlalchemy import or_
from .models import User, Sponsor, Influencer, Campaign, AdRequest
from flask_login import login_required, current_user, login_user, logout_user
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import io
from matplotlib.figure import Figure
from .models import User, Campaign, AdRequest
from sqlalchemy.orm import joinedload

routes = Blueprint('routes', __name__)
auth = Blueprint("authentication", __name__)

@routes.route('/')
def index():
    return render_template('index.html')

@routes.route('/admin_profile')
def admin_profile():
    ongoing_campaigns = Campaign.query.filter(Campaign.end_date >= datetime.now()).all()
    sponsor = Sponsor.query.all()
    influencer  = Influencer.query.all()
    flagged_campaigns = Campaign.query.filter_by(flagged=True).all()

    return render_template('admin_profile.html', 
                           ongoing_campaigns=ongoing_campaigns,
                           flagged_sponsors=sponsor,
                           flagged_influencers=influencer,
                           flagged_campaigns=flagged_campaigns)

 
@routes.route('/admin', methods=['GET', 'POST'])
def admin():
    if not current_user.is_authenticated:
        return render_template('home_adm.html')
    if current_user.role == 0:
        return redirect(url_for('routes.admin_profile'))
    return render_template('home_adm.html')

@routes.route('/sponsor_profile', methods=['GET', 'POST'])
@login_required
def sponsor_profile():
    sponsor = Sponsor.query.filter_by(user_id=current_user.user_id).first()
    if not sponsor:
        abort(404)

    campaigns = Campaign.query.filter_by(sponsor_id=sponsor.sponsor_id).all()

    # Calculate the progress for each campaign
    today = datetime.today().date()
    for campaign in campaigns:
        total_days = (campaign.end_date - campaign.start_date).days
        elapsed_days = (today - campaign.start_date).days
        campaign.progress = max(0, min(100, (elapsed_days / total_days) * 100)) if total_days > 0 else 0
    
    ad_requests = AdRequest.query.join(Campaign).filter(Campaign.sponsor_id == sponsor.sponsor_id).all()

    return render_template("sponsor_profile.html", user=current_user, campaigns=campaigns, ad_requests =ad_requests)


@routes.route('/influencer_profile', methods=['GET', 'POST'])
@login_required
def influencer_profile():
    influencer = Influencer.query.filter_by(user_id=current_user.user_id).first()
    if not influencer:
        abort(404)

    campaigns = AdRequest.query.filter_by(influencer_id=influencer.influencer_id, status='Accepted').all()
    accepted_requests = AdRequest.query.filter_by(influencer_id=influencer.influencer_id, status='Accepted').all()
    requests = AdRequest.query.filter_by(influencer_id=influencer.influencer_id, status = 'Pending').all()

    today = datetime.today().date()
    for campaign in campaigns:
        total_days = (campaign.campaign.end_date - campaign.campaign.start_date).days
        elapsed_days = (today - campaign.campaign.start_date).days
        campaign.progress = max(0, min(100, (elapsed_days / total_days) * 100)) if total_days > 0 else 0

    if request.method == 'POST':
        ad_request_id = request.form.get('ad_request_id')
        action = request.form.get('action')
        ad_request = AdRequest.query.filter_by(ad_request_id=ad_request_id, influencer_id=influencer.influencer_id).first()

        if ad_request:
            if action == 'accept':
                ad_request.status = 'Accepted'
            elif action == 'reject':
                ad_request.status = 'Rejected'

            db.session.commit()
            return redirect(url_for('routes.influencer_profile'))

    return render_template("influencer_profile.html", user=current_user, campaigns=campaigns, requests=requests, accepted_requests = accepted_requests)





@routes.route('/sponsor_campaigns', methods=['GET', 'POST'])
@login_required
def sponsor_campaigns():
    sponsor = Sponsor.query.filter_by(user_id=current_user.user_id).first()

    if not sponsor:
        abort(404)

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d').date()
        end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d').date()
        budget = float(request.form.get('budget'))
        visibility = request.form.get('visibility') == 'public'  # Convert to boolean

        # Validate budget and date constraints
        if budget < 0:
            flash('Budget cannot be negative.', 'error')
            return redirect(url_for('routes.sponsor_campaigns'))

        if end_date <= start_date:
            flash('End date must be after start date.', 'error')
            return redirect(url_for('routes.sponsor_campaigns'))

        new_campaign = Campaign(
            sponsor_id=sponsor.sponsor_id,
            name=name,
            description=description,
            start_date=start_date,
            end_date=end_date,
            budget=budget,
            visibility=visibility,
        )
        db.session.add(new_campaign)
        db.session.commit()
        flash('New campaign added successfully!', 'success')
        return redirect(url_for('routes.sponsor_campaigns'))

    campaigns = Campaign.query.filter_by(sponsor_id=sponsor.sponsor_id).all()

    # Calculate the progress for each campaign
    today = datetime.today().date()
    for campaign in campaigns:
        total_days = (campaign.end_date - campaign.start_date).days
        elapsed_days = (today - campaign.start_date).days
        if total_days > 0:
            campaign.progress = min(100, round((elapsed_days / total_days) * 100, 2))
        else:
            campaign.progress = 0

    return render_template("sponsor_campaigns.html", user=current_user, campaigns=campaigns)


# Route to display campaign details and handle edit/delete actions
@routes.route('/sponsor_campaigns/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
def campaign_details(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)

    if request.method == 'POST':
        if request.form.get('action') == 'delete':
            AdRequest.query.filter_by(campaign_id=campaign_id).delete()
            db.session.delete(campaign)
            db.session.commit()
            flash('Campaign deleted successfully!', 'success')
            return redirect(url_for('routes.sponsor_campaigns'))
        elif request.form.get('action') == 'edit':
            return redirect(url_for('routes.edit_campaign', campaign_id=campaign.campaign_id))

    return render_template('campaign_details.html', campaign=campaign)


# Route to edit campaign details
@routes.route('/edit_campaign/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
def edit_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)

    if request.method == 'POST':
        # Fetch form data
        name = request.form.get('name')
        description = request.form.get('description')
        datesd = request.form.get('start_date')
        dateed = request.form.get('end_date')
        budget = request.form.get('budget')
        visibility = request.form.get('visibility')

        # Debugging prints
        print(f"Name: {name}, Description: {description}, Start Date: {datesd}, End Date: {dateed}, Budget: {budget}, Visibility: {visibility}")

        if not name or not description or not datesd or not dateed or not budget or not visibility:
            flash('All fields are required.', 'error')
            return redirect(url_for('routes.edit_campaign', campaign_id=campaign.campaign_id))

        try:
            datesd = datetime.strptime(datesd, '%Y-%m-%d').date()
            dateed = datetime.strptime(dateed, '%Y-%m-%d').date()
            budget = float(budget)
            visibility = visibility == 'public'

            # Validate budget and date constraints
            if budget < 0:
                flash('Budget cannot be negative.', 'error')
                return redirect(url_for('routes.edit_campaign', campaign_id=campaign.campaign_id))

            if dateed <= datesd:
                flash('End date must be after start date.', 'error')
                return redirect(url_for('routes.edit_campaign', campaign_id=campaign.campaign_id))

            # Update campaign details
            campaign.name = name
            campaign.description = description
            campaign.start_date = datesd
            campaign.end_date = dateed
            campaign.budget = budget
            campaign.visibility = visibility

            db.session.commit()
            flash('Campaign updated successfully!', 'success')
            return redirect(url_for('routes.sponsor_campaigns', campaign_id=campaign.campaign_id))

        except ValueError as ve:
            flash('Invalid input format.', 'error')
            return redirect(url_for('routes.edit_campaign', campaign_id=campaign.campaign_id))

    return render_template('edit_campaign.html', campaign=campaign)

@routes.route('/view_campaign/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
def view_ads(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)

    ads = AdRequest.query.filter_by(campaign_id=campaign_id).all()
    return render_template('view_campaign.html', campaign=campaign, ads=ads)




@routes.route('/find_influencer', methods=['GET', 'POST'])
def find_influencer():
    influencers = Influencer.query.all()

    if request.method == 'POST':
        search_query = request.form.get('search')
        
        if search_query:
            influencers = Influencer.query.filter(Influencer.name.ilike(f'%{search_query}%')).all()

    return render_template('find_influencer.html', influencers=influencers)




@routes.route('/find_campaigns', methods=['GET', 'POST'])
def find_campaigns():
    campaigns = Campaign.query.options(joinedload(Campaign.sponsor)).all()

    if request.method == 'POST':
        search_query = request.form.get('search')
        
        if search_query:
            # Query campaigns by name or sponsor's company name
            searched_campaigns = Campaign.query.join(Sponsor).filter(
                (Campaign.name.ilike(f'%{search_query}%')) |
                (Sponsor.company.ilike(f'%{search_query}%'))
            ).all()
            
            # Display only the found campaigns
            if searched_campaigns:
                return render_template('find_campaigns.html', campaigns=searched_campaigns)
            
            else:
                return render_template('not_found_campaigns.html')
    
    return render_template('find_campaigns.html', campaigns=campaigns)


@routes.route('/add_ad_request/<int:influencer_id>', methods=['GET', 'POST'])
@login_required
def add_ad_request(influencer_id):
    influencer = Influencer.query.get_or_404(influencer_id)
    
    # Fetch campaigns associated with the current sponsor
    sponsor = Sponsor.query.filter_by(user_id=current_user.user_id).first()
    campaigns = Campaign.query.filter_by(sponsor_id=sponsor.sponsor_id).all()
    
    if request.method == 'POST':
        # Gather form data
        campaign_id = request.form.get('campaign_id')
        messages = request.form.get('messages')
        requirements = (request.form.get('requirements')) 
        payment_amount = float(request.form.get('payment_amount'))
        status = "Pending"
        
        # Create new AdRequest instance
        ad_request = AdRequest(
            campaign_id=campaign_id,
            influencer_id=influencer_id,
            messages=messages,
            requirements=requirements,
            payment_amount=payment_amount,
            status=status
        )
        
        # Add to database
        db.session.add(ad_request)
        db.session.commit()
        
        # Redirect to a success page or back to influencer listing
        return redirect(url_for('routes.find_influencer'))
    
    return render_template('add_ad_request.html', influencer=influencer, campaigns=campaigns)


@routes.route('/request_ad/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
def request_ad(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    
    if request.method == 'POST':
        # Create a new ad request
        ad_request = AdRequest(
            campaign_id=campaign_id,
            influencer_id=current_user.influencer.influencer_id,
            status='Requested',  # Initial status when sponsor sends the request
            # Add any other relevant fields like messages, requirements, payment_amount
        )

        
        db.session.add(ad_request)
        db.session.commit()
        
        flash('Ad request sent successfully!', 'success')
        return redirect(url_for('routes.find_campaigns'))  # Redirect to campaigns page or another appropriate page
    
    return render_template('find_campaigns.html', campaign=campaign)


@routes.route('/give_ad/<int:ad_request_id>', methods=['GET', 'POST'])
@login_required
def give_ad(ad_request_id):
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    campaign_id = ad_request.campaign_id
    influencer_id = ad_request.influencer_id

    if request.method == 'POST':
        # Handle form submission for giving the ad
        messages = request.form.get('messages')
        requirements = request.form.get('requirements')
        payment_amount = float(request.form.get('payment_amount'))

        # Update the existing ad request with new data
        ad_request.messages = messages
        ad_request.requirements = requirements
        ad_request.payment_amount = payment_amount
        ad_request.status = 'Pending'  # or 'Accepted', based on your business logic

        db.session.commit()

        # Redirect to a success page or relevant page
        flash('Ad details updated successfully!', 'success')
        return redirect(url_for('routes.sponsor_profile'))  # Redirect to dashboard or another page

    return render_template('give_ad.html', ad_request=ad_request, campaign_id=campaign_id, influencer_id=influencer_id)

@routes.route('/reject_ad/<int:ad_request_id>')
def reject_ad(ad_request_id):
    # Fetch the ad request from the database
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    
    # Change the status to "Rejected"
    ad_request.status = 'Rejected'
    
    # Commit the change to the database
    db.session.commit()
    
    # Flash a message to indicate the request was rejected
    flash('Ad request has been rejected.', 'success')
    
    # Redirect back to the sponsor profile page
    return redirect(url_for('routes.sponsor_profile'))


@routes.route('/handle_ad_request', methods=['POST'])
@login_required
def handle_ad_request():
    if request.method == 'POST':
        ad_request_id = request.form.get('ad_request_id')
        action = request.form.get('action')
        
        # Fetch the current influencer associated with the logged-in user
        influencer = Influencer.query.filter_by(user_id=current_user.user_id).first()
        
        if not influencer:
            flash('Influencer profile not found.', 'error')
            return redirect(url_for('routes.influencer_profile'))

        # Fetch the ad request
        ad_request = AdRequest.query.filter_by(ad_request_id=ad_request_id, influencer_id=influencer.influencer_id, status='Pending').first()
        
        if not ad_request:
            flash('Ad request not found or already processed.', 'error')
            return redirect(url_for('routes.influencer_profile'))
        
        if action == 'accept':
            ad_request.status = 'Accepted'
            flash('Ad request accepted successfully.', 'success')
        elif action == 'reject':
            ad_request.status = 'Rejected'
            flash('Ad request rejected successfully.', 'success')
        elif action == 'negotiate':
            new_amount = request.form.get('new_amount')
            if new_amount:
                ad_request.payment_amount = float(new_amount)
                ad_request.status = 'Negotiating'
                flash('Negotiation started successfully.', 'success')
            else:
                flash('Please enter a valid amount for negotiation.', 'error')

        db.session.commit()
        return redirect(url_for('routes.influencer_profile'))

    # Redirect if method is not POST (though it should not happen if properly handled)
    return redirect(url_for('routes.influencer_profile'))

#AUTHENTICATION
@auth.route("/sponsor_logout")
@login_required
def sponsor_logout():
    logout_user()
    return redirect(url_for("routes.index"))

@auth.route("/sponsor_login", methods=['GET', 'POST'])
def sponsor_login():
    warnings = []
    if request.method == 'POST':
        input_uname = request.form.get("username")
        input_pass = request.form.get("pwd")

        auth_user = User.query.filter_by(username=input_uname).first()
        if auth_user:
            if check_password_hash(auth_user.password, input_pass):
                if auth_user.role == "1":
                    if auth_user.flagged == True:
                        return render_template("flagged_user.html")
                    else:
                        flash("Login successful!", category='success')
                        login_user(auth_user, remember=True)
                        return redirect(url_for('routes.sponsor_profile'))
            else:
                warnings.append('Incorrect password.')
        else:
            warnings.append('Username not found.')

    return render_template("sponsor_login.html", user=current_user, warnings=warnings)

@auth.route("/sponsor_signup", methods=['GET', 'POST'])
def sponsor_signup():
    warnings = []
    if request.method == 'POST':
        email = request.form.get("Email")
        username = request.form.get("username")
        pwd = request.form.get("pwd")
        pwdConfirm = request.form.get("confpwd")
        industry = request.form.get("industry")
        company = request.form.get("company")

        username_exists = User.query.filter_by(username=username).first()
        email_exists = User.query.filter_by(email=email).first()
  
        if email_exists:
            warnings.append('This email is already in use, please login.')

        if username_exists:
            warnings.append('This username has already been chosen, please choose another one.')
        if pwd != pwdConfirm:
            warnings.append('Passwords do not match.')
        if len(username) < 4:
            warnings.append('Please choose a longer username. Username length should be greater than 3 letters.')
        if len(pwd) < 4:
            warnings.append('Please choose a longer password. Password length should be greater than 3 letters.')


        if not warnings:
            # Create new user
            new_user = User(username=username, email=email, password=generate_password_hash(pwd, method='scrypt'), role=1)
            db.session.add(new_user)
            db.session.commit()

            # Create new influencer record
            new_sponsor = Sponsor(user_id=new_user.user_id, industry = industry, company = company)
            db.session.add(new_sponsor)
            db.session.commit()
            login_user(new_user, remember=True)
            flash("User created!")
            return redirect(url_for('routes.sponsor_profile'))


    return render_template("sponsor_signup.html", user=current_user, warnings=warnings)


@auth.route("/influencer_logout")
@login_required
def influencer_logout():
    logout_user()
    return redirect(url_for("routes.index"))



@auth.route("/influencer_login", methods=['GET', 'POST'])
def influencer_login():
    warnings = []
    if request.method == 'POST':
        input_uname = request.form.get("username")
        input_pass = request.form.get("pwd")

        auth_user = User.query.filter_by(username=input_uname).first()
        if auth_user:
            if check_password_hash(auth_user.password, input_pass):
                if auth_user.role == "2":
                    if auth_user.flagged == True:
                        return render_template("flagged_user.html")
                    else:
                        flash("Login successful!", category='success')
                        login_user(auth_user, remember=True)
                        return redirect(url_for('routes.influencer_profile'))
            else:
                warnings.append('Incorrect password.')
        else:
            warnings.append('Username not found.')

    return render_template("influencer_login.html", user=current_user, warnings=warnings)

@auth.route("/influencer_signup", methods=['GET', 'POST'])
def influencer_signup():
    warnings = []
    if request.method == 'POST':
        email = request.form.get("Email")
        username = request.form.get("username")
        pwd = request.form.get("pwd")
        pwdConfirm = request.form.get("confpwd")
        niche = request.form.get("niche")  # Retrieve niche from form
        followers = request.form.get("followers")
        # Basic validations
        if len(username) < 4:
            warnings.append('Please choose a longer username (at least 4 characters).')
        if len(pwd) < 4:
            warnings.append('Please choose a longer password (at least 4 characters).')
        if pwd != pwdConfirm:
            warnings.append('Passwords do not match.')

        # Check if username already exists
        email_exists = User.query.filter_by(email=email).first()
  
        if email_exists:
            warnings.append('This email is already in use, please login.')

        username_exists = User.query.filter_by(username=username).first()
        if username_exists:
            warnings.append('This username has already been chosen, please choose another one.')

        if not warnings:
            # Create new user
            new_user = User(username=username, email=email, password=generate_password_hash(pwd, method='scrypt'), role=2)
            db.session.add(new_user)
            db.session.commit()

            # Create new influencer record
            new_influencer = Influencer(user_id=new_user.user_id, name=username, niche=niche,  followers=followers)
            db.session.add(new_influencer)
            db.session.commit()
            login_user(new_user, remember=True)
            flash("User created!")
            return redirect(url_for('routes.influencer_profile'))
        
    return render_template("influencer_signup.html", user=current_user, warnings=warnings)



@auth.route("/admin_logout")
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for("routes.index"))



@auth.route("/admin_login", methods=['GET', 'POST'])
def admin_login():
    warnings = []
    if request.method == 'POST':
        input_uname = request.form.get("admin_username")
        input_pass = request.form.get("admin_pwd")

        user = User.query.filter_by(username=input_uname).first()
        if user:
            if check_password_hash(user.password, input_pass):
                if user.role == "0":
                    flash("Logged in!", category='success')
                    login_user(user, remember=True)
                    return redirect(url_for('routes.admin'))

            else:
                warnings.append('Wrong Password')
                flash('Password is incorrect.', category='error')
        else:
            warnings.append('User does not exist')
            flash('Username does not exist.', category='error')
        # Redirect back to admin login page if credentials are incorrect

    return render_template("admin_login.html", customer_user=current_user, warnings = warnings)

@auth.route("/admin_signup", methods=['GET', 'POST'])
def admin_signup():
    warnings = []
    if request.method == 'POST':
        email = request.form.get("email")
        username = request.form.get("username")
        pwd = request.form.get("pwd")
        pwdConfirm = request.form.get("confpwd")

        username_exists = User.query.filter_by(username=username).first()
        email_exists = User.query.filter_by(email=email).first()
  
        if email_exists:
            warnings.append('This email is already in use, please login.')
        if username_exists:
            warnings.append('This username has already been chosen, please choose another one.')
        if pwd != pwdConfirm:
            warnings.append('Passwords do not match.')
        if len(username) < 4:
            warnings.append('Please choose a longer username. Username length should be greater than 3 letters.')
        if len(pwd) < 4:
            warnings.append('Please choose a longer password. Password length should be greater than 3 letters.')

        if not warnings:
            newUser = User(username=username, email=email, password=generate_password_hash(pwd, method='scrypt'), role=0)
            db.session.add(newUser)
            db.session.commit()
            login_user(newUser, remember=True)
            flash("User created!")
            return redirect(url_for('routes.admin'))

    return render_template("admin_signup.html", user=current_user, warnings=warnings)


@routes.route('/admin_influencer', methods=['GET', 'POST'])
def admin_influencer():
    influencers = Influencer.query.all()

    if request.method == 'POST':
        search_query = request.form.get('search')
        
        if search_query:
            searched_influencers = Influencer.query.filter(Influencer.name.ilike(f'%{search_query}%')).all()
            # Display only one influencer if found
            if influencers:
                return render_template('admin_influencer.html', influencers=searched_influencers)
    
    return render_template('admin_influencer.html', influencers=influencers)

@routes.route('/flag_influencer/<int:influencer_id>', methods=['POST'])
@login_required
def flag_influencer(influencer_id):
    influencer = Influencer.query.get_or_404(influencer_id)
    user = User.query.get(influencer.user_id)
    
    if user:
        user.flagged = True
        db.session.commit()
        flash('Influencer flagged successfully!', 'success')
    else:
        flash('User not found!', 'error')

    return redirect(url_for('routes.admin_influencer'))

@routes.route('/unflag_influencer/<int:influencer_id>', methods=['POST'])
def unflag_influencer(influencer_id):
    influencer = Influencer.query.get_or_404(influencer_id)
    if influencer.user.flagged:
        influencer.user.flagged = False
        db.session.commit()
        flash(f'Influencer {influencer.user.username} unflagged successfully.', 'success')
    else:
        flash(f'Influencer {influencer.user.username} is not flagged.', 'info')
    return redirect(url_for('admin_profile'))



@routes.route('/flag_sponsor/<int:sponsor_id>', methods=['POST'])
def flag_sponsor(sponsor_id):
    sponsor = Sponsor.query.get_or_404(sponsor_id)
    user = User.query.get(sponsor.user_id)    
    if user:
        user.flagged = True
        db.session.commit()
        flash('Sponsor flagged successfully!', 'success')
    else:
        flash('User not found!', 'error')
    return redirect(url_for('routes.admin_profile'))

# Route to unflag a sponsor
@routes.route('/unflag_sponsor/<int:sponsor_id>', methods=['POST'])
def unflag_sponsor(sponsor_id):
    sponsor = Sponsor.query.get_or_404(sponsor_id)
    if sponsor.user.flagged:
        sponsor.user.flagged = False
        db.session.commit()
        flash(f'Sponsor {sponsor.user.username} unflagged successfully.', 'success')
    else:
        flash(f'Sponsor {sponsor.user.username} is not flagged.', 'info')
    return redirect(url_for('admin_profile'))


@routes.route('/admin/unflag_user/<int:user_id>', methods=['POST'])
def unflag_user(user_id):
    user = User.query.get_or_404(user_id)

    # Update the flagged status to False
    user.flagged = False

    try:
        db.session.commit()
        flash(f'User "{user.username}" has been unflagged successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error occurred while unflagging user "{user.username}". Error: {str(e)}', 'error')

    # Redirect back to the admin profile page
    return redirect(url_for('routes.admin_profile'))

@routes.route('/admin_campaigns/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
def flag_campaigns(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    campaign.flagged = True
    AdRequest.query.filter_by(campaign_id=campaign_id).delete()
    db.session.commit()
    flash('Campaign Flagged successfully!', 'success')
    return redirect(url_for('routes.admin_profile'))

@routes.route('/admin_campaigns_flagged/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
def unflag_campaigns(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    campaign.flagged = False
    db.session.commit()
    flash('Campaign Unflagged successfully!', 'success')
    return redirect(url_for('routes.admin_profile'))


@routes.route('/admin_campaigns', methods=['GET', 'POST'])
def admin_campaigns():
    campaigns = Campaign.query.all()

    if request.method == 'POST':
        search_query = request.form.get('search')
        
        if search_query:
            searched_campaigmns = Campaign.query.filter(Campaign.name.ilike(f'%{search_query}%')).all()
            # Display only one influencer if found
            if searched_campaigmns:
                return render_template('admin_campaigns.html', campaigns=searched_campaigmns)
    
    return render_template('admin_campaigns.html', campaigns=campaigns)


@routes.route('/admin_statistics')
@login_required
def admin_statistics():
    active_users_count = User.query.filter_by(flagged=False).count()
    flagged_users_count = User.query.filter_by(flagged=True).count()
    total_campaigns_count = Campaign.query.count()
    public_campaigns_count = Campaign.query.filter_by(visibility=True).count()
    private_campaigns_count = Campaign.query.filter_by(visibility=False).count()
    ad_requests = AdRequest.query.all()

    ad_request_statuses = {
        "Pending": 0,
        "Accepted": 0,
        "Rejected": 0,
        "Requested": 0
    }

    for request in ad_requests:
        ad_request_statuses[request.status] += 1

    return render_template('admin_statistics.html',
                           active_users_count=active_users_count,
                           flagged_users_count=flagged_users_count,
                           total_campaigns_count=total_campaigns_count,
                           public_campaigns_count=public_campaigns_count,
                           private_campaigns_count=private_campaigns_count,
                           ad_request_statuses=ad_request_statuses)


@routes.route('/plot/users.png')
@login_required
def plot_users():
    active_users_count = User.query.filter_by(flagged=False).count()
    flagged_users_count = User.query.filter_by(flagged=True).count()

    fig = Figure()
    ax = fig.subplots()
    ax.pie([active_users_count, flagged_users_count], labels=['Active Users', 'Flagged Users'],
           autopct='%1.1f%%', colors=['#36a2eb', '#ff6384'])
    ax.set_title('User Status Distribution')

    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    buf.seek(0)
    return send_file(buf, mimetype='image/png')


@routes.route('/plot/campaigns.png')
@login_required
def plot_campaigns():
    total_campaigns_count = Campaign.query.count()
    public_campaigns_count = Campaign.query.filter_by(visibility=True).count()
    private_campaigns_count = Campaign.query.filter_by(visibility=False).count()

    fig = Figure()
    ax = fig.subplots()
    ax.bar(['Total', 'Public', 'Private'], [total_campaigns_count, public_campaigns_count, private_campaigns_count],
           color=['#4bc0c0', '#ffcd56', '#ff9f40'])
    ax.set_title('Campaigns Distribution')

    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    buf.seek(0)
    return send_file(buf, mimetype='image/png')


@routes.route('/plot/ad_requests.png')
@login_required
def plot_ad_requests():
    ad_requests = AdRequest.query.all()

    # Initialize the dictionary with only the relevant statuses
    ad_request_statuses = {
        "Accepted": 0,
        "Rejected": 0
    }

    for request in ad_requests:
        status = request.status.capitalize()  # Capitalize to match keys
        if status in ad_request_statuses:
            ad_request_statuses[status] += 1

    fig = Figure()
    ax = fig.subplots()
    ax.bar(ad_request_statuses.keys(), ad_request_statuses.values(), color=['#4bc0c0', '#ff6384'])
    ax.set_title('Ad Requests Status Distribution')
    ax.set_ylabel('Number of Requests')

    # Set y-ticks to range from 1 to the maximum count in ad_request_statuses
    max_requests = max(ad_request_statuses.values())
    ax.set_yticks(range(1, max_requests + 1))

    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    buf.seek(0)
    return send_file(buf, mimetype='image/png')



@routes.route('/adminfind_influencers', methods=['GET', 'POST'])
@login_required
def find_influencers():
    if request.method == 'POST':
        search_query = request.form.get('search')
        if search_query:
            # Perform the search using a case-insensitive filter
            influencers = Influencer.query.join(User).filter(
                or_(
                    Influencer.name.ilike(f'%{search_query}%'),
                    Influencer.niche.ilike(f'%{search_query}%'),
                    User.username.ilike(f'%{search_query}%')
                )
            ).all()
        else:
            influencers = []

        return render_template('admin_influencer.html', influencers=influencers)

    return render_template('admin_influencer.html', influencers=[])

@routes.route('/admin_sponsors', methods=['GET', 'POST'])
@login_required
def admin_sponsors():
    if request.method == 'POST':
        search_query = request.form.get('search')
        if search_query:
            # Search sponsors based on the query
            sponsors = Sponsor.query.join(User).filter(
                or_(
                    Sponsor.company.ilike(f'%{search_query}%'),
                    Sponsor.industry.ilike(f'%{search_query}%'),
                    User.username.ilike(f'%{search_query}%')
                )
            ).all()
        else:
            # No search query provided, show all sponsors
            sponsors = Sponsor.query.join(User).all()
    else:
        # GET request, show all sponsors
        sponsors = Sponsor.query.join(User).all()

    return render_template('admin_sponsors.html', sponsors=sponsors)