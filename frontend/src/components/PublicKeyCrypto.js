import React, { useState } from 'react';
import { Card, Form, Input, Select, Button, Space, message, Tabs } from 'antd';
import { CopyOutlined } from '@ant-design/icons';
import axios from 'axios';

const { Option } = Select;
const { TextArea } = Input;
const { TabPane } = Tabs;

const PublicKeyCrypto = () => {
  const [form] = Form.useForm();
  const [result, setResult] = useState('');
  const [loading, setLoading] = useState(false);
  const [keys, setKeys] = useState({});

  const handleGenerateKeys = async (algorithm) => {
    try {
      setLoading(true);
      const response = await axios.post('http://localhost:5000/generate', {
        algorithm: algorithm,
      });
      setKeys(response.data);
      message.success('密钥生成成功');
    } catch (error) {
      message.error('密钥生成失败：' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleEncrypt = async () => {
    try {
      const values = await form.validateFields();
      setLoading(true);
      const response = await axios.post('http://localhost:5000/encrypt', {
        algorithm: values.algorithm,
        publickey: values.publickey,
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
        privatekey: values.privatekey,
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

  const handleSign = async () => {
    try {
      const values = await form.validateFields();
      setLoading(true);
      const response = await axios.post('http://localhost:5000/sign', {
        algorithm: values.algorithm,
        privatekey: values.privatekey,
        plaintext: values.plaintext,
      });
      setResult(response.data.signature);
      message.success('签名成功');
    } catch (error) {
      message.error('签名失败：' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    try {
      const values = await form.validateFields();
      setLoading(true);
      const response = await axios.post('http://localhost:5000/verify', {
        algorithm: values.algorithm,
        publickey: values.publickey,
        plaintext: values.plaintext,
        signature: values.signature,
      });
      setResult(response.data.result);
      message.success('验证成功');
    } catch (error) {
      message.error('验证失败：' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(result);
    message.success('已复制到剪贴板');
  };

  return (
    <Card title="公钥密码算法" className="algorithm-card">
      <Tabs defaultActiveKey="1">
        <TabPane tab="加密/解密" key="1">
          <Form
            form={form}
            layout="vertical"
            initialValues={{ algorithm: 'RSA' }}
          >
            <Form.Item
              name="algorithm"
              label="算法选择"
              rules={[{ required: true, message: '请选择算法' }]}
            >
              <Select>
                <Option value="RSA">RSA</Option>
                <Option value="ECC">ECC</Option>
              </Select>
            </Form.Item>

            <Form.Item>
              <Button type="primary" onClick={() => handleGenerateKeys(form.getFieldValue('algorithm'))} loading={loading}>
                生成密钥对
              </Button>
            </Form.Item>

            <Form.Item
              name="publickey"
              label="公钥"
              rules={[{ required: true, message: '请输入公钥' }]}
            >
              <TextArea rows={4} placeholder="请输入公钥" value={keys.publickey} />
            </Form.Item>

            <Form.Item
              name="privatekey"
              label="私钥"
              rules={[{ required: true, message: '请输入私钥' }]}
            >
              <TextArea rows={4} placeholder="请输入私钥" value={keys.privatekey} />
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
          </Form>
        </TabPane>

        <TabPane tab="签名/验证" key="2">
          <Form
            form={form}
            layout="vertical"
            initialValues={{ algorithm: 'RSA-SHA1' }}
          >
            <Form.Item
              name="algorithm"
              label="算法选择"
              rules={[{ required: true, message: '请选择算法' }]}
            >
              <Select>
                <Option value="RSA-SHA1">RSA-SHA1</Option>
                <Option value="ECDSA">ECDSA</Option>
              </Select>
            </Form.Item>

            <Form.Item>
              <Button type="primary" onClick={() => handleGenerateKeys(form.getFieldValue('algorithm'))} loading={loading}>
                生成密钥对
              </Button>
            </Form.Item>

            <Form.Item
              name="publickey"
              label="公钥"
              rules={[{ required: true, message: '请输入公钥' }]}
            >
              <TextArea rows={4} placeholder="请输入公钥" value={keys.publickey} />
            </Form.Item>

            <Form.Item
              name="privatekey"
              label="私钥"
              rules={[{ required: true, message: '请输入私钥' }]}
            >
              <TextArea rows={4} placeholder="请输入私钥" value={keys.privatekey} />
            </Form.Item>

            <Form.Item
              name="plaintext"
              label="原文"
              rules={[{ required: true, message: '请输入原文' }]}
            >
              <TextArea rows={4} placeholder="请输入原文" />
            </Form.Item>

            <Form.Item
              name="signature"
              label="签名"
              rules={[{ required: true, message: '请输入签名' }]}
            >
              <TextArea rows={4} placeholder="请输入签名" />
            </Form.Item>

            <div className="operation-buttons">
              <Button type="primary" onClick={handleSign} loading={loading}>
                签名
              </Button>
              <Button onClick={handleVerify} loading={loading}>
                验证
              </Button>
            </div>
          </Form>
        </TabPane>
      </Tabs>

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
    </Card>
  );
};

export default PublicKeyCrypto; 