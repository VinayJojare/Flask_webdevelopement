from website import create_app

app = create_app()
application = app  # not neccessary

if __name__ == "__main__":
    app.run(debug=True)
