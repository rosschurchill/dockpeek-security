from flask_cors import CORS
from flask_login import LoginManager

# Inicjalizujemy rozszerzenia tutaj, aby uniknąć cyklicznych importów
cors = CORS()
login_manager = LoginManager()
login_manager.login_view = 'auth.login' # 'auth' to nazwa blueprint, 'login' to nazwa funkcji widoku