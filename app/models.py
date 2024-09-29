from app import db, login_manager
from flask_login import UserMixin # Этот класс даёт возможность работать с пользователем

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) # Эта строчка будет отправлять в БД запрос для поиска определённого юзера по его ID

login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) # Эта строчка будет отправлять в БД запрос для поиска определённого юзера по его ID


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):  # Функция, чтобы представить информацию о пользователе в виде одной строки
        return f'User: {self.username}, email: {self.emai}'




