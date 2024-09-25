from flask import Flask, request, jsonify, make_response
from flask_restx import Api, Resource,fields
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import imaplib
import email
from email.header import decode_header
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer

# local imports 
from config import DevConfig
from models import User, Inbox
from exts import db

app = Flask(__name__)
app.config.from_object(DevConfig)
CORS(app)
db.init_app(app,)
migrate = Migrate(app, db)
JWTManager(app)
api = Api(app,doc="/docs")



user_model = api.model(
    "User",{
        "userid" : fields.Integer(),
        "username" : fields.String(),
        "userPassword" : fields.String()
    }
)


inbox_model = api.model(
    "Inbox", {
        "owner" : fields.String(),
        "inboxemail" : fields.String(),
        "inboxpw" : fields.String(),
        "emailids" : fields.List(fields.String()),
        "unreadids" : fields.List(fields.String()),
    }
)


register_model = api.model(
    "Register",{
        "username" : fields.String(),
        "userEmail" : fields.String(),
        "userPassword" : fields.String()
    }
)


login_model = api.model(
    "Login", {
        "username": fields.String(), 
        "userPassword": fields.String()
    }
)


email_model = api.model(
    "Email", {
        "recipient": fields.String(),
        "emailid": fields.Integer(),
        "subject": fields.String(),
        "senderEmail": fields.String(),
        "dateReceived": fields.DateTime(),
        "sentimentvals" : fields.List(fields.Integer())
    }
)

def findSentiment(text):
    return [0, 0, 0, 0]

@app.shell_context_processor
def make_shell_context():
    return {
        "db": db,
        "User":User
    }
     

@api.route("/")
class Login(Resource):
    @api.expect(login_model)
    def post(self):
        data = request.get_json()
        username = data.get("username")
        userPassword = data.get("userPassword")
        old_user = User.query.filter_by(username=username).first()
        if old_user and check_password_hash(old_user.userPassword, userPassword):
            access_token = create_access_token(identity=old_user.username)
            refresh_token = create_refresh_token(identity=old_user.username) 
            return jsonify(
                {"access_token": access_token, "refresh_token": refresh_token,}
            )

@api.route("/register")
class Register(Resource):
    @api.expect(register_model)
    def post(self):
        data = request.get_json()
        username = data.get("username")
        old_user = User.query.filter_by(username=username).first()
        if old_user:
            return jsonify({"message": "This username is not available"})
        new_user = User(
            username = data.get("username"),
            userPassword = generate_password_hash(data.get("userPassword"))
        )
        new_user.save()
        return make_response(jsonify({"message": "Account was created successfully!"}))

@api.route("/dashboard/<username>")
class inboxesResource(Resource):
    @api.expect(inbox_model)
    @api.marshal_list_with(inbox_model)
    def get(self, username):
        inboxes = Inbox.query.filter_by(owner=username).all()
        if type(inboxes) == list:
            return inboxes
        else:
            return [inboxes]

    def post(self, username):
        data = request.get_json()
        inboxemail = data.get("inboxemail")
        pw = data.get("inboxpw")
        imap_server = "outlook.office365.com"
        imap = imaplib.IMAP4_SSL(imap_server)
        old_inbox = Inbox.query.filter_by(owner=username, inboxemail=inboxemail).first()
        if old_inbox:
            return jsonify({"message": "This username is not available"})
        try:
            imap.login(inboxemail, pw)
        except:
            return jsonify({"message": "Incorrect username or password!"})
        new_inbox = Inbox(
            owner = username,
            inboxpw = pw,
            inboxemail = inboxemail,
            unreadids = data.get("unreadids"),
            emailids = data.get("emailids"),
        )
        new_inbox.save()
        imap.close()
        return make_response(jsonify({"message": "Inbox has been successfully created!"}))


@api.route("/<username>/<inboxemail>/emails")
class emailsResource(Resource):
    def get(self, username, inboxemail):
        emails = []
        inboxobj = Inbox.query.filter_by(owner=username, inboxemail=inboxemail).first()
        pw = inboxobj.inboxpw
        
        imap_server = "outlook.office365.com"
        imap = imaplib.IMAP4_SSL(imap_server)
        imap.login(inboxemail, pw)
        status, messages = imap.select("INBOX")
        N = int(messages[0])
        if N > 50:
            N = 50
        messages = int(messages[0])
        for i in range(messages, messages-N, -1):
            res, msg = imap.fetch(str(i), "(RFC822)")
            for response in msg:
                if isinstance(response, tuple):
                    msg = email.message_from_bytes(response[1])
                    subject, encoding = decode_header(msg["Subject"])[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding)
                    From, encoding = decode_header(msg.get("From"))[0]
                    Date, encoding = decode_header(msg.get("Date"))[0]
                    messageID, encoding = decode_header(msg.get("Message-ID"))[0]
                    if isinstance(From, bytes):
                        From = From.decode(encoding)
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            content_disposition = str(part.get("Content-Disposition"))
                            try:
                                body = part.get_payload(decode=True).decode()
                            except:
                                pass
                            if content_type == "text/plain" and "attachment" not in content_disposition:
                                contents = body
                    else:
                        content_type = msg.get_content_type()
                        body = msg.get_payload(decode=True).decode()
                        if content_type == "text/plain":
                            contents=body
            
            sentiment = SentimentIntensityAnalyzer()   
            vals = sentiment.polarity_scores(contents)
            result=subject
            if len(subject) > 25:
                result = subject[:25] + "..."
            From=From.split(" <")[0]
            mail = {
                    "emailid" : messageID,
                    "subject": result,
                    "senderEmail": From,
                    "recipient": inboxemail,
                    "dateReceived": Date[:-7],
                    "sentimentvals": vals,
                }
            emails.append(mail)
        return jsonify({"emails": emails})
    
    def post(self, username, inboxemail):
        emails = []
        data = request.get_json()
        sentiments = data.get("sentiment")
        print(f"sentiment:{sentiments}")
        inboxobj = Inbox.query.filter_by(owner=username, inboxemail=inboxemail).first()
        pw = inboxobj.inboxpw
        imap_server = "outlook.office365.com"
        imap = imaplib.IMAP4_SSL(imap_server)
        imap.login(inboxemail, pw)
        status, messages = imap.select("INBOX")
        N = int(messages[0])
        if N > 50:
            N = 50
        messages = int(messages[0])
        for i in range(messages, messages-N, -1):
            res, msg = imap.fetch(str(i), "(RFC822)")
            for response in msg:
                if isinstance(response, tuple):
                    msg = email.message_from_bytes(response[1])
                    subject, encoding = decode_header(msg["Subject"])[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding)
                    From, encoding = decode_header(msg.get("From"))[0]
                    Date, encoding = decode_header(msg.get("Date"))[0]
                    messageID, encoding = decode_header(msg.get("Message-ID"))[0]
                    if isinstance(From, bytes):
                        From = From.decode(encoding)
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            content_disposition = str(part.get("Content-Disposition"))
                            try:
                                body = part.get_payload(decode=True).decode()
                            except:
                                pass
                            if content_type == "text/plain" and "attachment" not in content_disposition:
                                contents = body
                    else:
                        content_type = msg.get_content_type()
                        body = msg.get_payload(decode=True).decode()
                        if content_type == "text/plain":
                            contents=body
            sentiment = SentimentIntensityAnalyzer()   
            vals = sentiment.polarity_scores(contents)
            result=subject
            if len(subject) > 25:
                result = subject[:25] + "..."
            From=From.split(" <")[0]
            mail = {
                    "emailid" : messageID,
                    "subject": result,
                    "senderEmail": From,
                    "recipient": inboxemail,
                    "dateReceived": Date[:-7],
                    "sentimentvals": vals,
                }
            emails.append(mail)
        if sentiments != "date":
            mergesort(emails, sentiments)
        return jsonify({"emails": emails})


@api.route("/refresh")
class RefreshResource(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user)
        return make_response(jsonify({"access_token" : new_access_token}), 200)


@api.route("/inbox/<inboxemail>")
class inboxResource(Resource):
    @jwt_required()
    @api.marshal_with(inbox_model)
    def put(self, inboxemail):
        inbox_to_update=Inbox.query.get_or_404(inboxemail)
        data=request.get_json()
        inbox_to_update.update(data.get("emailCount"), data.get("emailids"), data.get("unreadids", data.get("upatedTime")))
        return inbox_to_update

    @jwt_required()
    @api.marshal_with(inbox_model)
    def delete(self, inboxemail):
        inbox_to_delete= Inbox.query.get_or_404(inboxemail)
        inbox_to_delete.delete()
        return inbox_to_delete

def mergesort(emails, sentiment):
    if len(emails) > 1:
        mid = len(emails) // 2
        left = emails[:mid]
        right = emails[mid:]
        mergesort(left, sentiment)
        mergesort(right, sentiment)
        i, j, k = 0
        while i < len(left) and j < len(right):
            if left[i]["sentimentvals"][sentiment] >= right[j]["sentimentvals"][sentiment]:
              emails[k] = left[i]
              i += 1
            else:
                emails[k] = right[j]
                j += 1
            k += 1
        while i < len(left):
            emails[k] = left[i]
            i += 1
            k += 1
        while j < len(right):
            emails[k]=right[j]
            j += 1
            k += 1

if __name__ == "__main__":
    app.run(debug=True)



