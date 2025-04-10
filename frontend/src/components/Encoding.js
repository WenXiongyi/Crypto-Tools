import React, { useState } from 'react';
import { Card, Form, Input, Select, Button, Space, message } from 'antd';
import { CopyOutlined } from '@ant-design/icons';
import axios from 'axios';

const { Option } = Select;
const { TextArea } = Input;

const Encoding = () => {
  const [form] = Form.useForm();
  const [result, setResult] = useState('');
  const [loading, setLoading] = useState(false);

  const handleEncode = async () => {
    try {
      const values = await form.validateFields();
      setLoading(true);
      const response = await axios.post('http://localhost:5000/encode', {
        algorithm: values.algorithm,
        plaintext: values.plaintext,
      });
      setResult(response.data.encoded);
      message.success('编码成功');
    } catch (error) {
      message.error('编码失败：' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDecode = async () => {
    try {
      const values = await form.validateFields();
      setLoading(true);
      const response = await axios.post('http://localhost:5000/decode', {
        algorithm: values.algorithm,
        ciphertext: values.ciphertext,
      });
      setResult(response.data.decoded);
      message.success('解码成功');
    } catch (error) {
      message.error('解码失败：' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(result);
    message.success('已复制到剪贴板');
  };

  return (
    <Card title="编码算法" className="algorithm-card">
      <Form
        form={form}
        layout="vertical"
        initialValues={{ algorithm: 'Base64' }}
      >
        <Form.Item
          name="algorithm"
          label="算法选择"
          rules={[{ required: true, message: '请选择编码算法' }]}
        >
          <Select>
            <Option value="Base64">Base64</Option>
            <Option value="UTF-8">UTF-8</Option>
          </Select>
        </Form.Item>

        <Form.Item
          name="plaintext"
          label="原始文本"
          rules={[{ required: true, message: '请输入原始文本' }]}
        >
          <TextArea rows={4} placeholder="请输入要编码的文本" />
        </Form.Item>

        <Form.Item
          name="ciphertext"
          label="编码文本"
          rules={[{ required: true, message: '请输入编码文本' }]}
        >
          <TextArea rows={4} placeholder="请输入要解码的文本" />
        </Form.Item>

        <div className="operation-buttons">
          <Button type="primary" onClick={handleEncode} loading={loading}>
            编码
          </Button>
          <Button onClick={handleDecode} loading={loading}>
            解码
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

export default Encoding; 