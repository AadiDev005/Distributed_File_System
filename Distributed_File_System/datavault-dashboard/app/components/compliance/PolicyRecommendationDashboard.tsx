'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Brain, 
  Lightbulb, 
  TrendingUp, 
  Shield, 
  Clock,
  DollarSign,
  CheckCircle,
  AlertTriangle,
  Filter,
  Download,
  Play,
  Settings,
  Lock
} from 'lucide-react';
import { PolicyRecommendationEngine, PolicyRecommendation } from '../../lib/policy/policyRecommendationEngine';

export default function PolicyRecommendationDashboard() {
  const [engine] = useState(() => PolicyRecommendationEngine.getInstance());
  const [recommendations, setRecommendations] = useState<PolicyRecommendation[]>([]);
  const [isGenerating, setIsGenerating] = useState(false);
  const [selectedIndustry, setSelectedIndustry] = useState<string>('healthcare');
  const [selectedRegulations, setSelectedRegulations] = useState<string[]>(['GDPR', 'HIPAA']);
  const [riskTolerance, setRiskTolerance] = useState<'low' | 'medium' | 'high'>('medium');
  const [budget, setBudget] = useState<'low' | 'medium' | 'high'>('medium');

  useEffect(() => {
    generateRecommendations();
  }, [selectedIndustry, selectedRegulations, riskTolerance, budget]);

  const generateRecommendations = async () => {
    setIsGenerating(true);
    
    try {
      const context = {
        industry: selectedIndustry,
        fileTypes: ['medical_record', 'financial_data', 'personal_info', 'confidential_doc'],
        userRoles: ['doctor', 'nurse', 'admin', 'patient'],
        complianceRequirements: selectedRegulations,
        currentPolicies: [], // Simulate no existing policies
        riskTolerance,
        budget
      };

      const newRecommendations = await engine.generateRecommendations(context);
      setRecommendations(newRecommendations);
    } catch (error) {
      console.error('Error generating recommendations:', error);
    } finally {
      setIsGenerating(false);
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'data-retention': return Clock;
      case 'access-control': return Shield;
      case 'encryption': return Lock;
      case 'audit': return CheckCircle;
      case 'privacy': return AlertTriangle;
      default: return Settings;
    }
  };

  const implementPolicy = (recommendation: PolicyRecommendation) => {
    // Simulate policy implementation
    alert(`Implementing: ${recommendation.title}\n\nThis would:\n- Create automated policy rules\n- Set up monitoring\n- Configure compliance checks\n- Generate audit trails`);
  };

  const exportRecommendations = () => {
    const exportData = {
      timestamp: new Date(),
      context: { selectedIndustry, selectedRegulations, riskTolerance, budget },
      recommendations: recommendations.map(r => ({
        title: r.title,
        priority: r.priority,
        estimatedROI: r.estimatedROI,
        riskReduction: r.riskReduction,
        implementationCost: r.implementationCost,
        reasoning: r.reasoning
      }))
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `policy-recommendations-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-gray-900">AI Policy Recommendation Engine</h2>
          <p className="text-gray-600 mt-1">Intelligent compliance automation with ML-powered policy suggestions</p>
        </div>
        <div className="flex space-x-3">
          <motion.button
            onClick={generateRecommendations}
            disabled={isGenerating}
            className="apple-button-secondary"
            whileHover={{ scale: 1.02 }}
          >
            <Brain className={`w-4 h-4 mr-2 ${isGenerating ? 'animate-pulse' : ''}`} />
            {isGenerating ? 'Analyzing...' : 'Regenerate'}
          </motion.button>
          <motion.button
            onClick={exportRecommendations}
            className="apple-button"
            whileHover={{ scale: 1.02 }}
          >
            <Download className="w-4 h-4 mr-2" />
            Export Report
          </motion.button>
        </div>
      </div>

      {/* Configuration Panel */}
      <div className="apple-card p-6">
        <h3 className="text-lg font-semibold mb-4">AI Analysis Configuration</h3>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Industry</label>
            <select
              value={selectedIndustry}
              onChange={(e) => setSelectedIndustry(e.target.value)}
              className="apple-input"
            >
              <option value="healthcare">Healthcare</option>
              <option value="finance">Financial Services</option>
              <option value="government">Government</option>
              <option value="education">Education</option>
              <option value="manufacturing">Manufacturing</option>
              <option value="technology">Technology</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Regulations</label>
            <div className="space-y-2">
              {['GDPR', 'HIPAA', 'SOX', 'PCI-DSS', 'CCPA'].map((regulation) => (
                <label key={regulation} className="flex items-center">
                  <input
                    type="checkbox"
                    checked={selectedRegulations.includes(regulation)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedRegulations([...selectedRegulations, regulation]);
                      } else {
                        setSelectedRegulations(selectedRegulations.filter(r => r !== regulation));
                      }
                    }}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="ml-2 text-sm text-gray-700">{regulation}</span>
                </label>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Risk Tolerance</label>
            <select
              value={riskTolerance}
              onChange={(e) => setRiskTolerance(e.target.value as any)}
              className="apple-input"
            >
              <option value="low">Conservative (Low Risk)</option>
              <option value="medium">Balanced (Medium Risk)</option>
              <option value="high">Aggressive (High Risk)</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Budget</label>
            <select
              value={budget}
              onChange={(e) => setBudget(e.target.value as any)}
              className="apple-input"
            >
              <option value="low">Limited Budget</option>
              <option value="medium">Moderate Budget</option>
              <option value="high">High Budget</option>
            </select>
          </div>
        </div>
      </div>

      {/* Recommendations Summary */}
      {recommendations.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <motion.div 
            className="apple-card p-6 text-center"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Lightbulb className="w-6 h-6 text-blue-600" />
            </div>
            <div className="text-2xl font-bold text-gray-900 mb-1">{recommendations.length}</div>
            <div className="text-sm text-gray-600">AI Recommendations</div>
          </motion.div>

          <motion.div 
            className="apple-card p-6 text-center"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
          >
            <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <TrendingUp className="w-6 h-6 text-green-600" />
            </div>
            <div className="text-2xl font-bold text-gray-900 mb-1">
              {Math.round(recommendations.reduce((sum, r) => sum + r.estimatedROI, 0) / recommendations.length)}%
            </div>
            <div className="text-sm text-gray-600">Avg ROI</div>
          </motion.div>

          <motion.div 
            className="apple-card p-6 text-center"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
          >
            <div className="w-12 h-12 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Shield className="w-6 h-6 text-purple-600" />
            </div>
            <div className="text-2xl font-bold text-gray-900 mb-1">
              {Math.round(recommendations.reduce((sum, r) => sum + r.riskReduction, 0) / recommendations.length)}%
            </div>
            <div className="text-sm text-gray-600">Risk Reduction</div>
          </motion.div>

          <motion.div 
            className="apple-card p-6 text-center"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
          >
            <div className="w-12 h-12 bg-orange-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <AlertTriangle className="w-6 h-6 text-orange-600" />
            </div>
            <div className="text-2xl font-bold text-gray-900 mb-1">
              {recommendations.filter(r => r.priority === 'critical').length}
            </div>
            <div className="text-sm text-gray-600">Critical Priority</div>
          </motion.div>
        </div>
      )}

      {/* Recommendations List */}
      <div className="space-y-6">
        {recommendations.map((recommendation, index) => {
          const CategoryIcon = getCategoryIcon(recommendation.category);
          
          return (
            <motion.div
              key={recommendation.id}
              className="apple-card overflow-hidden"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
            >
              <div className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-start space-x-4">
                    <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0">
                      <CategoryIcon className="w-6 h-6 text-blue-600" />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <h3 className="text-lg font-semibold text-gray-900">{recommendation.title}</h3>
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${getPriorityColor(recommendation.priority)}`}>
                          {recommendation.priority.toUpperCase()}
                        </span>
                        <span className="text-xs text-gray-500 bg-gray-100 px-2 py-1 rounded-full">
                          {recommendation.category.replace('-', ' ').toUpperCase()}
                        </span>
                      </div>
                      <p className="text-gray-600 mb-4">{recommendation.description}</p>
                      
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                        <div className="text-center p-3 bg-green-50 rounded-lg">
                          <div className="text-lg font-bold text-green-600">{recommendation.estimatedROI}%</div>
                          <div className="text-xs text-gray-600">ROI</div>
                        </div>
                        <div className="text-center p-3 bg-blue-50 rounded-lg">
                          <div className="text-lg font-bold text-blue-600">{recommendation.riskReduction}%</div>
                          <div className="text-xs text-gray-600">Risk Reduction</div>
                        </div>
                        <div className="text-center p-3 bg-purple-50 rounded-lg">
                          <div className="text-lg font-bold text-purple-600">{recommendation.timeToImplement}</div>
                          <div className="text-xs text-gray-600">Timeline</div>
                        </div>
                        <div className="text-center p-3 bg-orange-50 rounded-lg">
                          <div className="text-lg font-bold text-orange-600">{recommendation.affectedFiles.toLocaleString()}</div>
                          <div className="text-xs text-gray-600">Files Affected</div>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="flex space-x-2">
                    <motion.button
                      onClick={() => implementPolicy(recommendation)}
                      className="apple-button text-sm"
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                    >
                      <Play className="w-4 h-4 mr-1" />
                      Implement
                    </motion.button>
                  </div>
                </div>

                {/* AI Reasoning */}
                <div className="bg-gray-50 rounded-lg p-4 mb-4">
                  <h4 className="font-semibold text-gray-900 mb-2 flex items-center">
                    <Brain className="w-4 h-4 mr-2 text-blue-600" />
                    AI Analysis & Reasoning
                  </h4>
                  <ul className="text-sm text-gray-700 space-y-1">
                    {recommendation.reasoning.map((reason, idx) => (
                      <li key={idx} className="flex items-start">
                        <span className="text-blue-600 mr-2">•</span>
                        {reason}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Regulations */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="text-sm text-gray-600">Regulations:</span>
                    <div className="flex space-x-1">
                      {recommendation.regulation.map((reg) => (
                        <span key={reg} className="text-xs bg-blue-100 text-blue-700 px-2 py-1 rounded-full">
                          {reg}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="flex items-center space-x-4 text-sm text-gray-500">
                    <span>Confidence: {recommendation.confidence}%</span>
                    <span>Automation: {recommendation.automationLevel}</span>
                  </div>
                </div>
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Generate Loading State */}
      {isGenerating && (
        <div className="apple-card p-12 text-center">
          <Brain className="w-12 h-12 text-blue-600 mx-auto mb-4 animate-pulse" />
          <h3 className="text-lg font-semibold text-gray-900 mb-2">AI Engine Analyzing...</h3>
          <p className="text-gray-600">Processing compliance requirements and generating intelligent policy recommendations</p>
          <div className="mt-4 flex justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          </div>
        </div>
      )}
    </div>
  );
}
