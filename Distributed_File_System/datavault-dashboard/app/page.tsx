'use client';

import { motion } from 'framer-motion';
import { useState } from 'react';
import { Eye, EyeOff, ArrowRight, Shield, Lock, User } from 'lucide-react';
import { useRouter } from 'next/navigation';

export default function LoginPage() {
  const [showPassword, setShowPassword] = useState(false);
  const [credentials, setCredentials] = useState({ email: '', password: '' });
  const [isLoading, setIsLoading] = useState(false);
  const router = useRouter();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    
    setTimeout(() => {
      if (credentials.email && credentials.password) {
        localStorage.setItem('datavault-auth', 'authenticated');
        router.push('/dashboard');
      }
      setIsLoading(false);
    }, 1500);
  };

  return (
    <div className="min-h-screen bg-white">
      {/* Apple-style Navigation */}
      <nav className="apple-nav">
        <div className="apple-container">
          <div className="flex items-center justify-between h-16">
            <motion.div 
              className="flex items-center space-x-2"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
            >
              <Shield className="w-6 h-6 text-blue-600" />
              <span className="text-xl font-semibold">DataVault</span>
            </motion.div>
            
            <div className="hidden md:flex items-center space-x-8">
              {['Products', 'Enterprise', 'Security', 'Support'].map((item) => (
                <a
                  key={item}
                  href="#"
                  className="text-sm font-medium text-gray-800 hover:text-blue-600 transition-colors"
                >
                  {item}
                </a>
              ))}
            </div>

            <div className="flex items-center space-x-4">
              <a href="#" className="text-sm font-medium text-blue-600">
                Sign Up
              </a>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <div className="apple-section pt-20">
        <div className="text-center mb-16">
          <motion.h1 
            className="apple-headline mb-6"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            Welcome to DataVault Enterprise
          </motion.h1>
          <motion.p 
            className="apple-subheadline max-w-2xl mx-auto"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.2 }}
          >
            The world's most secure enterprise data platform with quantum-proof encryption and AI-powered compliance.
          </motion.p>
        </div>

        {/* Login Form */}
        <motion.div 
          className="max-w-md mx-auto"
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.4 }}
        >
          <div className="apple-card p-8">
            <div className="text-center mb-8">
              <h2 className="text-2xl font-semibold mb-2">Sign In</h2>
              <p className="text-gray-600">Access your secure enterprise dashboard</p>
            </div>

            <form onSubmit={handleLogin} className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Email Address
                </label>
                <input
                  type="email"
                  value={credentials.email}
                  onChange={(e) => setCredentials({...credentials, email: e.target.value})}
                  className="apple-input"
                  placeholder="Enter your email"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={credentials.password}
                    onChange={(e) => setCredentials({...credentials, password: e.target.value})}
                    className="apple-input pr-12"
                    placeholder="Enter your password"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-500 hover:text-gray-700"
                  >
                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <label className="flex items-center">
                  <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" />
                  <span className="ml-2 text-sm text-gray-600">Remember me</span>
                </label>
                <a href="#" className="text-sm text-blue-600 hover:text-blue-700">
                  Forgot password?
                </a>
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="apple-button w-full disabled:opacity-50"
              >
                {isLoading ? (
                  <div className="flex items-center justify-center">
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                    Signing in...
                  </div>
                ) : (
                  <div className="flex items-center justify-center">
                    Sign In
                    <ArrowRight className="w-4 h-4 ml-2" />
                  </div>
                )}
              </button>
            </form>

            {/* Demo Credentials */}
            <div className="mt-8 p-4 bg-blue-50 rounded-xl">
              <h4 className="text-sm font-semibold text-blue-900 mb-2">Demo Credentials:</h4>
              <div className="text-sm text-blue-700 space-y-1">
                <div>Email: <span className="font-mono">admin@datavault.com</span></div>
                <div>Password: <span className="font-mono">DataVault2025!</span></div>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Feature Highlights */}
        <motion.div 
          className="mt-20 grid grid-cols-1 md:grid-cols-3 gap-8"
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.6 }}
        >
          {[
            {
              icon: Shield,
              title: 'Quantum-Proof Security',
              description: 'CRYSTALS-Dilithium encryption protects against future quantum attacks'
            },
            {
              icon: Lock,
              title: 'Zero-Trust Architecture',
              description: 'Advanced microsegmentation and continuous authentication'
            },
            {
              icon: User,
              title: 'Enterprise Ready',
              description: 'Built for Fortune 500 companies with enterprise-grade compliance'
            }
          ].map((feature, index) => (
            <div key={index} className="apple-card p-6 text-center apple-hover">
              <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <feature.icon className="w-6 h-6 text-blue-600" />
              </div>
              <h3 className="text-lg font-semibold mb-2">{feature.title}</h3>
              <p className="text-gray-600 text-sm">{feature.description}</p>
            </div>
          ))}
        </motion.div>
      </div>
    </div>
  );
}
