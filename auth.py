from bottle import Bottle, request, response, abort
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from itsdangerous import TimedJSONWebSignatureSerializer as TJWSSerializer
from datetime import datetime
import json

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False, unique=True)
    hashed_password = Column(String, nullable=False)
    time_created = Column(DateTime, default=datetime.utcnow)
    disabled = Column(Boolean, default=False)

engine = create_engine('sqlite:///users.db')
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

app = Bottle()

@app.post('/auth')
def auth():
    data = request.json
    if not data or 'username' not in data or 'hashed_password' not in data:
        abort(400, 'Bad Request: Missing required fields.')

    username = data['username']
    hashed_password = data['hashed_password']

    session = Session()
    user = session.query(User).filter_by(username=username).first()

    if user and not user.disabled and user.hashed_password == hashed_password:
        s = TJWSSerializer('SECRET_KEY', expires_in=3600)
        token = s.dumps({'username': user.username, 'id': user.id}).decode('utf-8')
        return {'token': token}
    else:
        abort(401, 'Unauthorized: Invalid credentials.')

if __name__ == '__main__':
    app.run(host='localhost', port=8080)
