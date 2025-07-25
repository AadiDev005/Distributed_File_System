"use client";

import React, { useState, useEffect } from 'react';
import { 
  Play, 
  Pause, 
  CheckCircle, 
  Clock, 
  Users, 
  FileText, 
  Settings,
  Plus,
  Activity,
  Zap
} from 'lucide-react';

interface WorkflowTemplate {
  id: string;
  name: string;
  category: string;
  description: string;
  industry: string;
  use_case: string;
  created_at: string;
}

interface WorkflowStatus {
  status: string;
  total_workflows: number;
  total_instances: number;
  running_instances: number;
  completed_instances: number;
  available_templates: number;
  last_activity: string;
}

const WorkflowDashboard: React.FC = () => {
  const [workflowStatus, setWorkflowStatus] = useState<WorkflowStatus | null>(null);
  const [templates, setTemplates] = useState<WorkflowTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'templates' | 'instances'>('overview');

  useEffect(() => {
    fetchWorkflowData();
  }, []);

  const fetchWorkflowData = async () => {
    try {
      const [statusResponse, templatesResponse] = await Promise.all([
        fetch('http://localhost:3000/api/workflow/status'),
        fetch('http://localhost:3000/api/workflow/templates'),
      ]);

      const status = await statusResponse.json();
      const templatesData = await templatesResponse.json();

      setWorkflowStatus(status);
      setTemplates(templatesData.templates || []);
    } catch (error) {
      console.error('Failed to fetch workflow data:', error);
    } finally {
      setLoading(false);
    }
  };

  const startWorkflowFromTemplate = async (templateId: string) => {
    try {
      const response = await fetch('http://localhost:3000/api/workflow/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          workflow_id: templateId,
          user_id: 'current-user',
          variables: {
            started_from: 'dashboard',
            timestamp: new Date().toISOString(),
          },
        }),
      });

      const result = await response.json();
      if (result.success) {
        console.log('✅ Workflow started:', result.instance_id);
        fetchWorkflowData(); // Refresh data
      }
    } catch (error) {
      console.error('Failed to start workflow:', error);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-purple-600 to-blue-600 text-white rounded-lg p-6">
        <h1 className="text-3xl font-bold mb-2">
          📋 Workflow Management System
        </h1>
        <p className="text-purple-100">
          Week 29-32: Enterprise workflow automation and process management
        </p>
      </div>

      {/* Status Overview */}
      {workflowStatus && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="flex items-center space-x-2">
              <Activity className="h-5 w-5 text-blue-600" />
              <div>
                <p className="text-xs text-blue-600 uppercase font-medium">Status</p>
                <p className="text-lg font-bold text-blue-900">{workflowStatus.status}</p>
              </div>
            </div>
          </div>

          <div className="bg-green-50 border border-green-200 rounded-lg p-4">
            <div className="flex items-center space-x-2">
              <CheckCircle className="h-5 w-5 text-green-600" />
              <div>
                <p className="text-xs text-green-600 uppercase font-medium">Completed</p>
                <p className="text-lg font-bold text-green-900">{workflowStatus.completed_instances}</p>
              </div>
            </div>
          </div>

          <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
            <div className="flex items-center space-x-2">
              <Clock className="h-5 w-5 text-orange-600" />
              <div>
                <p className="text-xs text-orange-600 uppercase font-medium">Running</p>
                <p className="text-lg font-bold text-orange-900">{workflowStatus.running_instances}</p>
              </div>
            </div>
          </div>

          <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
            <div className="flex items-center space-x-2">
              <FileText className="h-5 w-5 text-purple-600" />
              <div>
                <p className="text-xs text-purple-600 uppercase font-medium">Templates</p>
                <p className="text-lg font-bold text-purple-900">{workflowStatus.available_templates}</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="bg-white rounded-lg border shadow-sm">
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 px-6">
            {[
              { id: 'overview', label: 'Overview', icon: Activity },
              { id: 'templates', label: 'Templates', icon: FileText },
              { id: 'instances', label: 'Active Workflows', icon: Clock },
            ].map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setActiveTab(id as any)}
                className={`flex items-center space-x-2 py-4 border-b-2 transition-colors ${
                  activeTab === id
                    ? 'border-blue-600 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span>{label}</span>
              </button>
            ))}
          </nav>
        </div>

        {/* Tab Content */}
        <div className="p-6">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-gray-50 rounded-lg p-6">
                  <h3 className="text-lg font-semibold mb-4">🚀 Quick Actions</h3>
                  <div className="space-y-3">
                    <button
                      onClick={() => setActiveTab('templates')}
                      className="w-full flex items-center justify-between p-3 bg-white rounded-lg border hover:border-blue-300 transition-colors"
                    >
                      <span className="flex items-center space-x-2">
                        <Plus className="h-4 w-4 text-blue-600" />
                        <span>Create New Workflow</span>
                      </span>
                      <span className="text-gray-400">→</span>
                    </button>
                    
                    <button
                      onClick={() => setActiveTab('instances')}
                      className="w-full flex items-center justify-between p-3 bg-white rounded-lg border hover:border-green-300 transition-colors"
                    >
                      <span className="flex items-center space-x-2">
                        <Activity className="h-4 w-4 text-green-600" />
                        <span>View Active Workflows</span>
                      </span>
                      <span className="text-gray-400">→</span>
                    </button>
                  </div>
                </div>

                <div className="bg-gray-50 rounded-lg p-6">
                  <h3 className="text-lg font-semibold mb-4">📊 System Health</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-600">System Status</span>
                      <span className="px-2 py-1 bg-green-100 text-green-800 rounded text-sm">
                        {workflowStatus?.status || 'Operational'}
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-600">Total Workflows</span>
                      <span className="font-semibold">{workflowStatus?.total_workflows || 0}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-600">Success Rate</span>
                      <span className="font-semibold text-green-600">
                        {workflowStatus ? 
                          Math.round((workflowStatus.completed_instances / Math.max(workflowStatus.total_instances, 1)) * 100) 
                          : 0}%
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'templates' && (
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <h3 className="text-lg font-semibold">Available Workflow Templates</h3>
                <button className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                  <Plus className="h-4 w-4" />
                  <span>Create Custom</span>
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {templates.map((template) => (
                  <div key={template.id} className="bg-white border rounded-lg p-4 hover:shadow-md transition-shadow">
                    <div className="flex justify-between items-start mb-3">
                      <h4 className="font-semibold text-gray-900">{template.name}</h4>
                      <span className="px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs">
                        {template.category}
                      </span>
                    </div>
                    
                    <p className="text-gray-600 text-sm mb-4 line-clamp-2">
                      {template.description}
                    </p>
                    
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-500">
                        {template.industry} • {template.use_case}
                      </span>
                      
                      <button
                        onClick={() => startWorkflowFromTemplate(template.id)}
                        className="flex items-center space-x-1 px-3 py-1 bg-blue-600 text-white rounded text-sm hover:bg-blue-700"
                      >
                        <Play className="h-3 w-3" />
                        <span>Start</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'instances' && (
            <div className="space-y-4">
              <h3 className="text-lg font-semibold">Active Workflow Instances</h3>
              
              <div className="bg-gray-50 rounded-lg p-8 text-center">
                <Clock className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <h4 className="text-lg font-medium text-gray-900 mb-2">No Active Workflows</h4>
                <p className="text-gray-600 mb-4">
                  Start a workflow from the templates to see active instances here.
                </p>
                <button
                  onClick={() => setActiveTab('templates')}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Browse Templates
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default WorkflowDashboard;
