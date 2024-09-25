from sqlalchemy.ext.mutable import MutableList

# local import
from exts import db

class User(db.Model):
    userid = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(25), nullable=False, unique=True)
    userPassword = db.Column(db.String(), nullable=False)

    def __repr__(self):
        return f"<User {self.username} >"

    def save(self):
        db.session.add(self)
        db.session.commit()
    
    def delete(self):
        db.session.delete(self)
        db.session.commit()
    
    def update(self, username, userPassword):
        self.username=username
        self.userPassword=userPassword

class Inbox(db.Model):
    inboxemail = db.Column(db.String(), primary_key=True)
    inboxpw = db.Column(db.String(), nullable=False)
    owner = db.Column(db.String(), nullable=False)
    emailids = db.Column(MutableList.as_mutable(db.PickleType), default=[], nullable=False)
    unreadids = db.Column(MutableList.as_mutable(db.PickleType), default=[], nullable=False)

    def __repr__(self):
        return f"<Inbox {self.inboxemail} >"

    def save(self):
        db.session.add(self)
        db.session.commit()
    
    def delete(self):
        db.session.delete(self)
        db.session.commit()
    
    def update(self, inboxemail, emailids, unreadids, owner, inboxpw):
        self.inboxemail = inboxemail
        self.inboxpw = inboxpw
        self.owner = owner
        self.emailids = emailids
        self.unreadids = unreadids
        db.session.commit()

class Email(db.Model):
    emailid = db.Column(db.String(), primary_key = True)
    recipient = db.Column(db.String(), nullable = False)
    subject = db.Column(db.Text(), nullable = False)
    senderEmail = db.Column(db.String(), primary_key = True)
    dateReceived = db.Column(db.DateTime(), nullable=False)
    sentimentvals = db.Column(MutableList.as_mutable(db.PickleType), default=[], nullable=False)

    def __repr__(self):
        return f"<Inbox {self.senderEmail} >"

    def save(self):
        db.session.add(self)
        db.session.commit()
    
    def delete(self):
        db.session.delete(self)
        db.session.commit()
    
    def update(self, emailid, subject, senderEmail, recipient, dateReceived, sentimentvals):
        self.emailid = emailid
        self.subject = subject
        self.senderEmail = senderEmail
        self.recipient = recipient
        self.dateReceived = dateReceived
        self.sentimentvals = sentimentvals
        db.session.commit()