import sys
import os

# 添加项目根目录到Python路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.app import app

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 