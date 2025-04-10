import React, { useState } from 'react';
import { Card, Form, Input, Select, Button, Space, message } from 'antd';
import { CopyOutlined } from '@ant-design/icons';
import axios from 'axios';

const { Option } = Select;
const { TextArea } = Input;

const SymmetricCrypto = () => {
  const [form] = Form.useForm();
  const [result, setResult] = useState('');
  const [loading, setLoading] = useState(false);

  const handleEncrypt = async () => {
    try {
      const values = await form.validateFields();
      setLoading(true);
      const response = await axios.post('http://localhost:5000/encrypt', {
        algorithm: values.algorithm,
        key: values.key,
        plaintext: values.plaintext,
      });
      setResult(response.data.ciphertext);
      message.success('加密成功');
    } catch (error) {
      message.error('加密失败：' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDecrypt = async () => {
    try {
      const values = await form.validateFields();
      setLoading(true);
      const response = await axios.post('http://localhost:5000/decrypt', {
        algorithm: values.algorithm,
        key: values.key,
        ciphertext: values.ciphertext,
      });
      setResult(response.data.plaintext);
      message.success('解密成功');
    } catch (error) {
      message.error('解密失败：' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(result);
    message.success('已复制到剪贴板');
  };

  return (
    <Card title="对称加密算法" className="algorithm-card">
      <Form
        form={form}
        layout="vertical"
        initialValues={{ algorithm: 'AES' }}
      >
        <Form.Item
          name="algorithm"
          label="算法选择"
          rules={[{ required: true, message: '请选择加密算法' }]}
        >
          <Select>
            <Option value="AES">AES</Option>
            <Option value="SM4">SM4</Option>
            <Option value="RC6">RC6</Option>
          </Select>
        </Form.Item>

        <Form.Item
          name="key"
          label="密钥"
          rules={[{ required: true, message: '请输入密钥' }]}
        >
          <Input placeholder="请输入密钥" />
        </Form.Item>

        <Form.Item
          name="plaintext"
          label="明文"
          rules={[{ required: true, message: '请输入明文' }]}
        >
          <TextArea rows={4} placeholder="请输入明文" />
        </Form.Item>

        <Form.Item
          name="ciphertext"
          label="密文"
          rules={[{ required: true, message: '请输入密文' }]}
        >
          <TextArea rows={4} placeholder="请输入密文" />
        </Form.Item>

        <div className="operation-buttons">
          <Button type="primary" onClick={handleEncrypt} loading={loading}>
            加密
          </Button>
          <Button onClick={handleDecrypt} loading={loading}>
            解密
          </Button>
        </div>

        {result && (
          <div className="result-area">
            <Space>
              <span>结果：</span>
              <span>{result}</span>
              <Button
                type="text"
                icon={<CopyOutlined />}
                onClick={copyToClipboard}
                className="copy-button"
              />
            </Space>
          </div>
        )}
      </Form>
    </Card>
  );
};

export default SymmetricCrypto; 