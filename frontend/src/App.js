import React from 'react';
import { Layout, Menu } from 'antd';
import { Routes, Route, Link } from 'react-router-dom';
import {
  LockOutlined,
  SafetyCertificateOutlined,
  KeyOutlined,
  CodeOutlined,
} from '@ant-design/icons';
import SymmetricCrypto from './components/SymmetricCrypto';
import HashAlgorithm from './components/HashAlgorithm';
import Encoding from './components/Encoding';
import PublicKeyCrypto from './components/PublicKeyCrypto';
import './App.css';

const { Header, Content, Sider } = Layout;

function App() {
  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Header className="header">
        <div className="logo" />
        <h1 style={{ color: 'white', margin: 0 }}>密码算法工具箱</h1>
      </Header>
      <Layout>
        <Sider width={200} className="site-layout-background">
          <Menu
            mode="inline"
            defaultSelectedKeys={['1']}
            style={{ height: '100%', borderRight: 0 }}
          >
            <Menu.Item key="1" icon={<LockOutlined />}>
              <Link to="/symmetric">对称加密</Link>
            </Menu.Item>
            <Menu.Item key="2" icon={<SafetyCertificateOutlined />}>
              <Link to="/hash">哈希算法</Link>
            </Menu.Item>
            <Menu.Item key="3" icon={<CodeOutlined />}>
              <Link to="/encoding">编码算法</Link>
            </Menu.Item>
            <Menu.Item key="4" icon={<KeyOutlined />}>
              <Link to="/public-key">公钥密码</Link>
            </Menu.Item>
          </Menu>
        </Sider>
        <Layout style={{ padding: '0 24px 24px' }}>
          <Content
            className="site-layout-background"
            style={{
              padding: 24,
              margin: 0,
              minHeight: 280,
            }}
          >
            <Routes>
              <Route path="/symmetric" element={<SymmetricCrypto />} />
              <Route path="/hash" element={<HashAlgorithm />} />
              <Route path="/encoding" element={<Encoding />} />
              <Route path="/public-key" element={<PublicKeyCrypto />} />
              <Route path="/" element={<SymmetricCrypto />} />
            </Routes>
          </Content>
        </Layout>
      </Layout>
    </Layout>
  );
}

export default App; 