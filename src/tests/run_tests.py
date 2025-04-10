import unittest
import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 导入所有测试模块
from tests.test_aes import TestAES
from tests.test_sm4 import TestSM4
from tests.test_rc6 import TestRC6
from tests.test_hash import TestHashAlgorithms
from tests.test_rsa import TestRSA
from tests.test_ecc import TestECC
from tests.test_encoding import TestEncoding

def create_test_suite():
    """创建测试套件"""
    suite = unittest.TestSuite()
    
    # 添加所有测试类
    suite.addTest(unittest.makeSuite(TestAES))
    suite.addTest(unittest.makeSuite(TestSM4))
    suite.addTest(unittest.makeSuite(TestRC6))
    suite.addTest(unittest.makeSuite(TestHashAlgorithms))
    suite.addTest(unittest.makeSuite(TestRSA))
    suite.addTest(unittest.makeSuite(TestECC))
    suite.addTest(unittest.makeSuite(TestEncoding))
    
    return suite

if __name__ == '__main__':
    # 创建测试套件
    test_suite = create_test_suite()
    
    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # 输出测试结果
    print("\n测试结果统计:")
    print(f"测试总数: {result.testsRun}")
    print(f"失败数: {len(result.failures)}")
    print(f"错误数: {len(result.errors)}")
    
    # 如果有测试失败，返回非零退出码
    if not result.wasSuccessful():
        sys.exit(1) 