from django.contrib.sessions.backends.cache import SessionStore as CacheSessionStore
from django_redis import get_redis_connection
import uuid

class CustomSessionStore(CacheSessionStore):
    def __init__(self, session_key=None):
        super().__init__(session_key)
        self.redis = get_redis_connection("default")
        self._session_key = session_key or self._get_new_session_key()
        self._session_cache = {}

    def _get_new_session_key(self):
        return str(uuid.uuid4())

    def save(self, must_create=False):
        if self.session_key is None:
            return self.create()
            
        if '_auth_user_id' in self._session:
            from django.contrib.auth.models import User
            user = User.objects.get(id=self._session['_auth_user_id'])
            # Используем redis клиент напрямую
            self.redis.delete(self.session_key)  # Удаляем старый ключ если есть
            self.redis.hset(
                self.session_key,
                mapping={
                    'username': user.username,
                    'user_id': str(user.id),
                    '_auth_user_id': self._session['_auth_user_id'],
                    '_auth_user_backend': self._session['_auth_user_backend'],
                    '_auth_user_hash': self._session['_auth_user_hash']
                }
            )
            return self.session_key
        return super().save(must_create)

    def load(self):
        if self.session_key is None:
            self._session_cache = {}
            return {}
        
        data = self.redis.hgetall(self.session_key)
        if not data:
            self._session_cache = {}
            return {}
            
        return {k.decode('utf-8'): v.decode('utf-8') for k, v in data.items()}

# Экспортируем класс как SessionStore
SessionStore = CustomSessionStore 