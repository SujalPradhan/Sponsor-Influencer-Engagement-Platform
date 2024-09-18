
# BrandFluence: Sponsor & Influencer Management System

This project is a web application designed to connect sponsors with influencers, allowing sponsors to manage campaigns and ad requests. The system provides separate login profiles for admins, sponsors, and influencers.

## Key Features

- **Admin Dashboard**: Manage users, view flagged sponsors and influencers, and monitor campaigns.
- **Sponsor Profile**: 
  - Manage and view active campaigns.
  - Accept or reject new ad requests from influencers.
  - Track campaign progress and influencer engagements.
- **Influencer Profile**:
  - View campaigns and ad requests.
  - Accept, reject, or negotiate offers from sponsors.
  - Track personal statistics like reach and engagement rate.
- **Authentication System**: Signup and login functionality for different roles (admin, sponsor, influencer).
- **Campaign Management**: Sponsors can create and manage campaigns, track their progress, and interact with influencers.
- **Ad Request Handling**: Allows sponsors to send requests to influencers and view their responses.

## Tech Stack

- **Backend**: Flask (Python)
- **Database**: SQLite (with SQLAlchemy for ORM)
- **Frontend**: HTML, CSS (custom styling for vibrant design)
- **Authentication**: Flask-Login, password hashing with `scrypt`
- **Sessions**: Session handling with timed expiration

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo.git
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Initialize the database:
   ```bash
   from project import initialize_app, db
   app = initialize_app()
   with app.app_context():
       db.create_all()
   ```

4. Run the application:
   ```bash
   python app.py
   ```

## Routes Overview

- `/admin_login`, `/sponsor_login`, `/influencer_login`: Role-based login pages.
- `/admin_profile`, `/sponser_profile`, `/influencer_profile`: Role-specific profile views.
- `/admin_signup`, `/sponsor_signup`, `/influencer_signup`: Registration pages for different user types.

## Grading

This project was a part of my IITM BS degree and was graded **S** (Outstanding) for its robust implementation and user-centric design.

---

