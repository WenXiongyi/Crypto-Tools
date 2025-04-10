import React, { useState } from 'react';
import { Card, Form, Input, Select, Button, Space, message } from 'antd';
import { CopyOutlined } from '@ant-design/icons';
import axios from 'axios';

const { Option } = Select;
const { TextArea } = Input;

const HashAlgorithm = () => {
  const [form] = Form.useForm();
  const [result, setResult] = useState('');
  const [loading, setLoading] = useState(false);

  const handleHash = async () => {
    try {
      const values = await form.validateFields();
      setLoading(true);
      const response = await axios.post('http://localhost:5000/hash', {
        algorithm: values.algorithm,
        plaintext: values.plaintext,
      });
      setResult(response.data.hash);
      message.success('哈希计算成功');
    } catch (error) {
      message.error('哈希计算失败：' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(result);
    message.success('已复制到剪贴板');
  };

  return (
    <Card title="哈希算法" className="algorithm-card">
      <Form
        form={form}
        layout="vertical"
        initialValues={{ algorithm: 'SHA256' }}
      >
        <Form.Item
          name="algorithm"
          label="算法选择"
          rules={[{ required: true, message: '请选择哈希算法' }]}
        >
          <Select>
            <Option value="SHA1">SHA1</Option>
            <Option value="SHA256">SHA256</Option>
            <Option value="SHA3">SHA3</Option>
            <Option value="RIPEMD160">RIPEMD160</Option>
            <Option value="HMACSHA1">HMAC-SHA1</Option>
            <Option value="HMACSHA256">HMAC-SHA256</Option>
            <Option value="PBKDF2">PBKDF2</Option>
          </Select>
        </Form.Item>

        <Form.Item
          name="plaintext"
          label="输入文本"
          rules={[{ required: true, message: '请输入文本' }]}
        >
          <TextArea rows={4} placeholder="请输入要计算哈希的文本" />
        </Form.Item>

        <div className="operation-buttons">
          <Button type="primary" onClick={handleHash} loading={loading}>
            计算哈希
          </Button>
        </div>

        {result && (
          <div className="result-area">
            <Space>
              <span>哈希值：</span>
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

export default HashAlgorithm; 