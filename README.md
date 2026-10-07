# KMARRY

Static website files are published through GitHub Pages. Firebase Authentication, Firestore, Storage, and callable Functions back registration and member data.

See [production setup](docs/production.md) for the admin account, Razorpay plan buttons, manual premium activation, and Firebase deployment steps. The temporary admin page is available at `/admin.html`; it uses the server-side `ADMIN_PASSWORD` Secret Manager value and signed sessions, separate from member Firebase Authentication. Never commit admin passwords to this repository.
