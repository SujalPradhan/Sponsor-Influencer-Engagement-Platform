from project import initialize_app, db

app = initialize_app()
with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(port=7000, debug=True)