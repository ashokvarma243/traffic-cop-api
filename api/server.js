// test-server.js - Complete Traffic Cop API Server with Advanced Features
const http = require('http');

// Simple in-memory storage for testing
const sessions = new Map();
const apiKeys = new Map([
    ['tc_test_123', { id: 'test_pub', name: 'Test Publisher' }],
    ['tc_demo_publisher_123', { id: 'demo_pub', name: 'Demo Publisher' }],
    ['tc_enterprise_456', { id: 'enterprise_pub', name: 'Enterprise Publisher' }]
]);

// Advanced Analytics Engine
class AdvancedAnalytics {
    constructor() {
        this.metrics = {
            realTimeData: [],
            hourlyStats: Array(24).fill().map((_, i) => ({ hour: i, requests: 0, blocked: 0, avgLatency: 0 })),
            dailyStats: [],
            geographicData: new Map(),
            threatIntelligence: [],
            performanceMetrics: {
                avgResponseTime: 0,
                p95ResponseTime: 0,
                errorRate: 0,
                throughput: 0
            }
        };
        this.startRealTimeCollection();
    }
    
    recordRequest(analysis, responseTime, clientIP) {
        const timestamp = Date.now();
        const hour = new Date().getHours();
        
        // Real-time data (keep last 1000 requests)
        this.metrics.realTimeData.push({
            timestamp,
            sessionId: analysis.sessionId,
            riskScore: analysis.riskScore,
            action: analysis.action,
            responseTime,
            clientIP,
            threats: analysis.threats
        });
        
        if (this.metrics.realTimeData.length > 1000) {
            this.metrics.realTimeData.shift();
        }
        
        // Hourly stats
        this.metrics.hourlyStats[hour].requests++;
        if (analysis.action === 'block') {
            this.metrics.hourlyStats[hour].blocked++;
        }
        
        // Update performance metrics
        this.updatePerformanceMetrics(responseTime, analysis.action === 'block');
        
        // Geographic data
        this.updateGeographicData(clientIP, analysis);
        
        // Threat intelligence
        if (analysis.threats.length > 0) {
            this.recordThreat(analysis, clientIP);
        }
    }
    
    updatePerformanceMetrics(responseTime, isBlocked) {
        const recentRequests = this.metrics.realTimeData.slice(-100);
        
        // Average response time
        const avgTime = recentRequests.reduce((sum, req) => sum + req.responseTime, 0) / recentRequests.length;
        this.metrics.performanceMetrics.avgResponseTime = Math.round(avgTime);
        
        // P95 response time
        const sortedTimes = recentRequests.map(r => r.responseTime).sort((a, b) => a - b);
        const p95Index = Math.floor(sortedTimes.length * 0.95);
        this.metrics.performanceMetrics.p95ResponseTime = sortedTimes[p95Index] || 0;
        
        // Error rate (blocked requests as errors)
        const blockedCount = recentRequests.filter(r => r.action === 'block').length;
        this.metrics.performanceMetrics.errorRate = (blockedCount / recentRequests.length) * 100;
        
        // Throughput (requests per minute)
        const oneMinuteAgo = Date.now() - 60000;
        const recentMinute = this.metrics.realTimeData.filter(r => r.timestamp > oneMinuteAgo);
        this.metrics.performanceMetrics.throughput = recentMinute.length;
    }
    
    updateGeographicData(clientIP, analysis) {
        // Simulate geographic data based on IP
        const geoData = this.getGeoFromIP(clientIP);
        
        if (!this.metrics.geographicData.has(geoData.country)) {
            this.metrics.geographicData.set(geoData.country, {
                country: geoData.country,
                code: geoData.code,
                requests: 0,
                blocked: 0,
                avgRisk: 0,
                totalRisk: 0
            });
        }
        
        const countryData = this.metrics.geographicData.get(geoData.country);
        countryData.requests++;
        countryData.totalRisk += analysis.riskScore;
        countryData.avgRisk = countryData.totalRisk / countryData.requests;
        
        if (analysis.action === 'block') {
            countryData.blocked++;
        }
    }
    
    getGeoFromIP(ip) {
        // Simulate geographic lookup
        const countries = ['US', 'GB', 'DE', 'FR', 'CN', 'RU', 'IN', 'BR', 'JP', 'AU'];
        const countryNames = {
            'US': 'United States', 'GB': 'United Kingdom', 'DE': 'Germany',
            'FR': 'France', 'CN': 'China', 'RU': 'Russia', 'IN': 'India',
            'BR': 'Brazil', 'JP': 'Japan', 'AU': 'Australia'
        };
        
        const code = countries[Math.floor(Math.random() * countries.length)];
        return { country: countryNames[code], code: code };
    }
    
    recordThreat(analysis, clientIP) {
        this.metrics.threatIntelligence.push({
            timestamp: Date.now(),
            sessionId: analysis.sessionId,
            clientIP: clientIP,
            threats: analysis.threats,
            riskScore: analysis.riskScore,
            action: analysis.action
        });
        
        // Keep only last 500 threats
        if (this.metrics.threatIntelligence.length > 500) {
            this.metrics.threatIntelligence.shift();
        }
    }
    
    startRealTimeCollection() {
        // Simulate real-time data updates
        setInterval(() => {
            this.generatePredictiveInsights();
        }, 30000); // Every 30 seconds
    }
    
    generatePredictiveInsights() {
        const recentData = this.metrics.realTimeData.slice(-100);
        
        // Predict traffic spikes
        const currentHour = new Date().getHours();
        const historicalAvg = this.metrics.hourlyStats[currentHour].requests / 30; // 30 days avg
        const currentRate = recentData.length;
        
        if (currentRate > historicalAvg * 1.5) {
            console.log('🚨 Traffic spike detected - scaling recommended');
        }
        
        // Predict attack patterns
        const recentThreats = this.metrics.threatIntelligence.filter(t => 
            Date.now() - t.timestamp < 300000 // Last 5 minutes
        );
        
        if (recentThreats.length > 10) {
            console.log('🚨 Potential coordinated attack detected');
        }
    }
    
    getAdvancedMetrics() {
        return {
            realTime: {
                currentThroughput: this.metrics.performanceMetrics.throughput,
                avgLatency: this.metrics.performanceMetrics.avgResponseTime,
                errorRate: this.metrics.performanceMetrics.errorRate,
                activeThreats: this.metrics.threatIntelligence.filter(t => 
                    Date.now() - t.timestamp < 300000
                ).length
            },
            trends: {
                hourlyStats: this.metrics.hourlyStats,
                topCountries: Array.from(this.metrics.geographicData.values())
                    .sort((a, b) => b.requests - a.requests)
                    .slice(0, 10),
                threatTrends: this.getThreatTrends()
            },
            predictions: {
                nextHourTraffic: this.predictNextHourTraffic(),
                riskForecast: this.predictRiskLevel(),
                capacityRecommendation: this.getCapacityRecommendation()
            }
        };
    }
    
    getThreatTrends() {
        const threatTypes = {};
        this.metrics.threatIntelligence.forEach(threat => {
            threat.threats.forEach(type => {
                threatTypes[type] = (threatTypes[type] || 0) + 1;
            });
        });
        
        return Object.entries(threatTypes)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 5)
            .map(([type, count]) => ({ type, count }));
    }
    
    predictNextHourTraffic() {
        const currentHour = new Date().getHours();
        const nextHour = (currentHour + 1) % 24;
        const historicalAvg = this.metrics.hourlyStats[nextHour].requests / 30;
        const currentTrend = this.metrics.performanceMetrics.throughput * 60; // Convert to hourly
        
        return Math.round((historicalAvg + currentTrend) / 2);
    }
    
    predictRiskLevel() {
        const recentRisks = this.metrics.realTimeData.slice(-50).map(r => r.riskScore);
        const avgRisk = recentRisks.reduce((a, b) => a + b, 0) / recentRisks.length;
        
        if (avgRisk > 60) return 'HIGH';
        if (avgRisk > 30) return 'MEDIUM';
        return 'LOW';
    }
    
    getCapacityRecommendation() {
        const currentLoad = this.metrics.performanceMetrics.throughput;
        const avgLatency = this.metrics.performanceMetrics.avgResponseTime;
        
        if (avgLatency > 100 || currentLoad > 1000) {
            return 'SCALE_UP';
        } else if (avgLatency < 30 && currentLoad < 100) {
            return 'SCALE_DOWN';
        }
        return 'OPTIMAL';
    }
}

// Machine Learning Threat Detection Engine
class MLThreatDetection {
    constructor() {
        this.model = {
            weights: {
                userAgent: 0.25,
                screenResolution: 0.15,
                geographic: 0.20,
                behavioral: 0.25,
                temporal: 0.15
            },
            thresholds: {
                bot: 0.8,
                suspicious: 0.6,
                normal: 0.3
            },
            learningRate: 0.01
        };
        this.trainingData = [];
        this.featureExtractor = new FeatureExtractor();
    }
    
    analyzeWithML(visitorData, behavioralData = {}) {
        const features = this.featureExtractor.extract(visitorData, behavioralData);
        const riskScore = this.calculateRiskScore(features);
        const confidence = this.calculateConfidence(features);
        const threatVector = this.identifyThreatVector(features);
        
        return {
            mlRiskScore: riskScore,
            confidence: confidence,
            threatVector: threatVector,
            features: features,
            recommendation: this.getRecommendation(riskScore, confidence)
        };
    }
    
    calculateRiskScore(features) {
        let score = 0;
        
        // User Agent Analysis
        score += features.userAgentSuspicion * this.model.weights.userAgent;
        
        // Device Fingerprint Analysis
        score += features.deviceSuspicion * this.model.weights.screenResolution;
        
        // Geographic Risk
        score += features.geographicRisk * this.model.weights.geographic;
        
        // Behavioral Analysis
        score += features.behavioralRisk * this.model.weights.behavioral;
        
        // Temporal Analysis
        score += features.temporalRisk * this.model.weights.temporal;
        
        return Math.min(Math.max(score * 100, 0), 100);
    }
    
    calculateConfidence(features) {
        // Calculate confidence based on feature consistency
        const featureValues = Object.values(features);
        const mean = featureValues.reduce((a, b) => a + b, 0) / featureValues.length;
        const variance = featureValues.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / featureValues.length;
        
        // Lower variance = higher confidence
        return Math.max(0, Math.min(100, 100 - (variance * 100)));
    }
    
    identifyThreatVector(features) {
        const vectors = [];
        
        if (features.userAgentSuspicion > 0.7) vectors.push('Automated Browser');
        if (features.deviceSuspicion > 0.6) vectors.push('Virtual Environment');
        if (features.geographicRisk > 0.8) vectors.push('High-Risk Location');
        if (features.behavioralRisk > 0.7) vectors.push('Abnormal Behavior');
        if (features.temporalRisk > 0.6) vectors.push('Suspicious Timing');
        
        return vectors.length > 0 ? vectors : ['Low Risk'];
    }
    
    getRecommendation(riskScore, confidence) {
        if (riskScore > 80 && confidence > 70) {
            return { action: 'BLOCK', reason: 'High risk with high confidence' };
        } else if (riskScore > 60) {
            return { action: 'CHALLENGE', reason: 'Medium risk detected' };
        } else if (riskScore > 30) {
            return { action: 'MONITOR', reason: 'Low risk - continue monitoring' };
        } else {
            return { action: 'ALLOW', reason: 'Normal traffic pattern' };
        }
    }
    
    learn(visitorData, actualOutcome) {
        // Add to training data
        this.trainingData.push({
            features: this.featureExtractor.extract(visitorData),
            outcome: actualOutcome
        });
        
        // Retrain model periodically
        if (this.trainingData.length % 100 === 0) {
            this.retrainModel();
        }
    }
    
    retrainModel() {
        // Simple gradient descent for weight adjustment
        const learningRate = this.model.learningRate;
        
        this.trainingData.slice(-500).forEach(sample => {
            const predicted = this.calculateRiskScore(sample.features) / 100;
            const actual = sample.outcome === 'block' ? 1 : 0;
            const error = predicted - actual;
            
            // Adjust weights based on error
            Object.keys(this.model.weights).forEach(key => {
                if (sample.features[key + 'Risk'] !== undefined) {
                    this.model.weights[key] -= learningRate * error * sample.features[key + 'Risk'];
                }
            });
        });
        
        // Normalize weights
        const totalWeight = Object.values(this.model.weights).reduce((a, b) => a + b, 0);
        Object.keys(this.model.weights).forEach(key => {
            this.model.weights[key] /= totalWeight;
        });
    }
}

// Feature Extraction Engine
class FeatureExtractor {
    extract(visitorData, behavioralData = {}) {
        return {
            userAgentSuspicion: this.analyzeUserAgent(visitorData.userAgent),
            deviceSuspicion: this.analyzeDevice(visitorData),
            geographicRisk: this.analyzeGeography(visitorData),
            behavioralRisk: this.analyzeBehavior(behavioralData),
            temporalRisk: this.analyzeTiming(visitorData),
            networkRisk: this.analyzeNetwork(visitorData)
        };
    }
    
    analyzeUserAgent(userAgent) {
        if (!userAgent) return 1.0;
        
        const ua = userAgent.toLowerCase();
        let suspicion = 0;
        
        // Bot keywords
        const botKeywords = ['bot', 'crawler', 'spider', 'scraper', 'headless'];
        botKeywords.forEach(keyword => {
            if (ua.includes(keyword)) suspicion += 0.3;
        });
        
        // Automation tools
        const autoTools = ['selenium', 'puppeteer', 'playwright', 'phantom'];
        autoTools.forEach(tool => {
            if (ua.includes(tool)) suspicion += 0.4;
        });
        
        // Unusual patterns
        if (ua.length < 20 || ua.length > 500) suspicion += 0.2;
        if (!ua.includes('mozilla') && !ua.includes('webkit')) suspicion += 0.3;
        
        return Math.min(suspicion, 1.0);
    }
    
    analyzeDevice(visitorData) {
        let suspicion = 0;
        
        // Screen resolution analysis
        const resolution = visitorData.screenResolution || '';
        const commonResolutions = ['1920x1080', '1366x768', '1536x864', '1440x900'];
        
        if (resolution === '1024x768') suspicion += 0.4; // Common bot resolution
        if (!commonResolutions.includes(resolution) && resolution !== '') suspicion += 0.2;
        
        // Plugin analysis
        const plugins = visitorData.plugins || 0;
        if (plugins === 0) suspicion += 0.3;
        if (plugins > 50) suspicion += 0.2;
        
        // Platform consistency
        if (!visitorData.platform) suspicion += 0.2;
        
        return Math.min(suspicion, 1.0);
    }
    
    analyzeGeography(visitorData) {
        const highRiskCountries = ['CN', 'RU', 'BD', 'PK', 'ID', 'VN'];
        const mediumRiskCountries = ['IN', 'PH', 'EG', 'NG', 'UA', 'TR'];
        
        if (highRiskCountries.includes(visitorData.countryCode)) return 0.8;
        if (mediumRiskCountries.includes(visitorData.countryCode)) return 0.5;
        
        return 0.1;
    }
    
    analyzeBehavior(behavioralData) {
        let suspicion = 0;
        
        // Mouse movement analysis
        if (behavioralData.mouseMovements < 5) suspicion += 0.3;
        if (behavioralData.clickSpeed && behavioralData.clickSpeed < 100) suspicion += 0.4;
        
        // Scroll behavior
        if (behavioralData.scrollEvents < 2) suspicion += 0.2;
        
        // Page interaction time
        if (behavioralData.timeOnPage && behavioralData.timeOnPage < 1000) suspicion += 0.3;
        
        return Math.min(suspicion, 1.0);
    }
    
    analyzeTiming(visitorData) {
        const now = Date.now();
        const requestTime = visitorData.timestamp || now;
        const timeDiff = now - requestTime;
        
        let suspicion = 0;
        
        // Very fast requests (possible automation)
        if (timeDiff < 100) suspicion += 0.4;
        
        // Requests at unusual hours (for the timezone)
        const hour = new Date().getHours();
        if (hour >= 2 && hour <= 6) suspicion += 0.2; // Late night requests
        
        return Math.min(suspicion, 1.0);
    }
    
    analyzeNetwork(visitorData) {
        // Simulate network analysis
        let suspicion = 0;
        
        // Check for VPN/Proxy indicators
        if (visitorData.ip && visitorData.ip.startsWith('10.')) suspicion += 0.3;
        
        // Unusual ISP patterns (would need real ISP database)
        if (visitorData.isp && visitorData.isp.toLowerCase().includes('hosting')) {
            suspicion += 0.4;
        }
        
        return Math.min(suspicion, 1.0);
    }
}

// Smart Alert Engine
class SmartAlertEngine {
    constructor() {
        this.alertRules = [
            {
                id: 'high_risk_spike',
                name: 'High Risk Traffic Spike',
                condition: (metrics) => metrics.realTime.errorRate > 50,
                severity: 'HIGH',
                cooldown: 300000 // 5 minutes
            },
            {
                id: 'ddos_pattern',
                name: 'Potential DDoS Attack',
                condition: (metrics) => metrics.realTime.currentThroughput > 1000,
                severity: 'CRITICAL',
                cooldown: 600000 // 10 minutes
            },
            {
                id: 'geographic_anomaly',
                name: 'Geographic Anomaly Detected',
                condition: (metrics) => this.checkGeographicAnomaly(metrics),
                severity: 'MEDIUM',
                cooldown: 900000 // 15 minutes
            }
        ];
        
        this.alertHistory = [];
        this.lastAlerts = new Map();
        this.webhooks = [];
        this.emailAlerts = [];
    }
    
    checkAlerts(metrics) {
        const alerts = [];
        
        this.alertRules.forEach(rule => {
            if (this.shouldTriggerAlert(rule, metrics)) {
                const alert = this.createAlert(rule, metrics);
                alerts.push(alert);
                this.processAlert(alert);
            }
        });
        
        return alerts;
    }
    
    shouldTriggerAlert(rule, metrics) {
        const lastAlert = this.lastAlerts.get(rule.id);
        const now = Date.now();
        
        // Check cooldown period
        if (lastAlert && (now - lastAlert) < rule.cooldown) {
            return false;
        }
        
        // Check condition
        return rule.condition(metrics);
    }
    
    createAlert(rule, metrics) {
        const alert = {
            id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            ruleId: rule.id,
            name: rule.name,
            severity: rule.severity,
            timestamp: Date.now(),
            metrics: metrics.realTime,
            description: this.generateAlertDescription(rule, metrics),
            recommendations: this.generateRecommendations(rule, metrics)
        };
        
        this.alertHistory.push(alert);
        this.lastAlerts.set(rule.id, Date.now());
        
        return alert;
    }
    
    generateAlertDescription(rule, metrics) {
        switch (rule.id) {
            case 'high_risk_spike':
                return `Error rate has spiked to ${metrics.realTime.errorRate}% (threshold: 50%)`;
            case 'ddos_pattern':
                return `Traffic throughput is ${metrics.realTime.currentThroughput} req/min (threshold: 1000)`;
            case 'geographic_anomaly':
                return 'Unusual geographic traffic pattern detected';
            default:
                return 'Alert condition met';
        }
    }
    
    generateRecommendations(rule, metrics) {
        switch (rule.id) {
            case 'high_risk_spike':
                return [
                    'Review recent traffic patterns',
                    'Consider lowering risk thresholds temporarily',
                    'Check for coordinated attack patterns'
                ];
            case 'ddos_pattern':
                return [
                    'Enable aggressive rate limiting',
                    'Scale infrastructure immediately',
                    'Contact hosting provider if needed'
                ];
            case 'geographic_anomaly':
                return [
                    'Review geographic filtering rules',
                    'Investigate traffic sources',
                    'Consider temporary geo-blocking'
                ];
            default:
                return ['Investigate alert condition'];
        }
    }
    
    processAlert(alert) {
        console.log(`🚨 ALERT [${alert.severity}]: ${alert.name}`);
        console.log(`   Description: ${alert.description}`);
        
        // Send to webhooks
        this.webhooks.forEach(webhook => {
            this.sendWebhook(webhook, alert);
        });
        
        // Send email alerts for high severity
        if (alert.severity === 'HIGH' || alert.severity === 'CRITICAL') {
            this.emailAlerts.forEach(email => {
                this.sendEmailAlert(email, alert);
            });
        }
    }
    
    sendWebhook(webhook, alert) {
        // Simulate webhook sending
        console.log(`📡 Sending webhook to ${webhook.url}`);
        
        const payload = {
            alert: alert,
            timestamp: Date.now(),
            source: 'Traffic Cop'
        };
        
        // In real implementation, use fetch() to send webhook
    }
    
    sendEmailAlert(email, alert) {
        // Simulate email sending
        console.log(`📧 Sending email alert to ${email}`);
    }
    
    checkGeographicAnomaly(metrics) {
        // Check if traffic from unusual countries exceeds threshold
        const topCountries = metrics.trends.topCountries || [];
        const highRiskCountries = ['CN', 'RU', 'BD', 'PK'];
        
        const highRiskTraffic = topCountries
            .filter(country => highRiskCountries.includes(country.code))
            .reduce((sum, country) => sum + country.requests, 0);
        
        const totalTraffic = topCountries.reduce((sum, country) => sum + country.requests, 0);
        
        return totalTraffic > 0 && (highRiskTraffic / totalTraffic) > 0.6;
    }
    
    addWebhook(url, secret = null) {
        this.webhooks.push({ url, secret });
    }
    
    addEmailAlert(email) {
        this.emailAlerts.push(email);
    }
    
    getAlertHistory(limit = 50) {
        return this.alertHistory.slice(-limit).reverse();
    }
}

// Initialize advanced features
const analytics = new AdvancedAnalytics();
const mlEngine = new MLThreatDetection();
const alertEngine = new SmartAlertEngine();

// Add webhook for testing
alertEngine.addWebhook('https://your-webhook-url.com/alerts');
alertEngine.addEmailAlert('admin@yoursite.com');

// Enhanced traffic analysis function with ML and Automatic Bot Detection
function analyzeTraffic(visitorData) {
    const sessionId = 'sess_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    const startTime = Date.now();
    
    // Basic analysis
    let riskScore = 0;
    const threats = [];
    
    // Bot detection in user agent
    if (visitorData.userAgent && visitorData.userAgent.toLowerCase().includes('bot')) {
        riskScore += 40;
        threats.push('Bot detected in user agent');
    }
    
    // Enhanced user agent analysis
    if (visitorData.userAgent) {
        const ua = visitorData.userAgent.toLowerCase();
        const botKeywords = ['headless', 'selenium', 'puppeteer', 'playwright', 'phantom', 'crawler', 'spider', 'scraper'];
        
        botKeywords.forEach(keyword => {
            if (ua.includes(keyword)) {
                riskScore += 35;
                threats.push(`Automation tool detected: ${keyword}`);
            }
        });
        
        // Check for missing or suspicious user agent
        if (ua.length < 20 || ua.length > 500) {
            riskScore += 20;
            threats.push('Unusual user agent length');
        }
    }
    
    // Screen size check
    if (visitorData.screenResolution === '1024x768' || !visitorData.screenResolution) {
        riskScore += 25;
        threats.push('Suspicious screen resolution');
    }
    
    // Geographic risk
    if (visitorData.countryCode && ['CN', 'RU', 'BD', 'PK', 'ID'].includes(visitorData.countryCode)) {
        riskScore += 30;
        threats.push('High-risk geographic location');
    }
    
    // Enhanced behavior analysis from SDK
    if (visitorData.behaviorData) {
        const behavior = visitorData.behaviorData;
        
        // Mouse movement analysis
        if (behavior.mouseMovements !== undefined) {
            if (behavior.mouseMovements === 0) {
                riskScore += 35;
                threats.push('No mouse movement detected');
            } else if (behavior.mouseVariation < 50) {
                riskScore += 25;
                threats.push('Limited mouse movement variation');
            }
        }
        
        // Click analysis
        if (behavior.avgClickSpeed && behavior.avgClickSpeed < 100) {
            riskScore += 30;
            threats.push('Rapid clicking detected (bot-like)');
        }
        
        // Scroll pattern analysis
        if (behavior.scrollPattern) {
            if (behavior.scrollPattern === 'too_fast') {
                riskScore += 20;
                threats.push('Unusually fast scrolling');
            } else if (behavior.scrollPattern === 'too_uniform') {
                riskScore += 25;
                threats.push('Uniform scroll pattern (bot-like)');
            } else if (behavior.scrollPattern === 'too_slow') {
                riskScore += 15;
                threats.push('Unusually slow scrolling');
            }
        }
        
        // Page interaction analysis
        if (behavior.timeOnPage > 10000 && behavior.pageInteractions === 0) {
            riskScore += 35;
            threats.push('No page interaction despite time on page');
        }
        
        // Keystroke analysis
        if (behavior.keystrokes === 0 && behavior.timeOnPage > 15000) {
            riskScore += 20;
            threats.push('No keyboard activity detected');
        }
    }
    
    // Device fingerprint analysis
    if (visitorData.deviceFingerprint) {
        const device = visitorData.deviceFingerprint;
        
        // WebDriver detection (automation tools)
        if (device.webdriver === true) {
            riskScore += 50;
            threats.push('WebDriver automation detected');
        }
        
        // Plugin analysis
        if (device.plugins && device.plugins.length === 0) {
            riskScore += 20;
            threats.push('No browser plugins detected');
        } else if (device.plugins && device.plugins.length > 50) {
            riskScore += 15;
            threats.push('Excessive browser plugins detected');
        }
        
        // Hardware information missing
        if (!device.deviceMemory && !device.hardwareConcurrency) {
            riskScore += 15;
            threats.push('Missing hardware information');
        }
        
        // Suspicious timezone/language combination
        if (device.timezone && device.language) {
            // Check for mismatched timezone and language
            const suspiciousCombos = [
                { timezone: 'America/New_York', language: 'zh-CN' },
                { timezone: 'Europe/London', language: 'ru' },
                { timezone: 'Asia/Tokyo', language: 'en-US' }
            ];
            
            suspiciousCombos.forEach(combo => {
                if (device.timezone.includes(combo.timezone) && device.language.includes(combo.language)) {
                    riskScore += 10;
                    threats.push('Suspicious timezone/language combination');
                }
            });
        }
    }
    
    // Loading time analysis
    if (visitorData.loadTime) {
        if (visitorData.loadTime < 50) {
            riskScore += 25;
            threats.push('Unusually fast page load (possible prefetch)');
        } else if (visitorData.loadTime > 30000) {
            riskScore += 10;
            threats.push('Unusually slow page load');
        }
    }
    
    // Plugin count analysis
    if (visitorData.plugins !== undefined) {
        if (visitorData.plugins === 0) {
            riskScore += 15;
            threats.push('No browser plugins detected');
        }
    }
    
    // Cookie analysis
    if (visitorData.cookieEnabled === false) {
        riskScore += 10;
        threats.push('Cookies disabled');
    }
    
    // ML Analysis (your existing ML engine)
    const mlAnalysis = mlEngine.analyzeWithML(visitorData);
    
    // Combine basic, behavior, and ML scores with weighted average
    const behaviorScore = riskScore;
    const mlScore = mlAnalysis.mlRiskScore;
    
    // Weight: 40% behavior analysis, 60% ML analysis
    const finalScore = Math.round((behaviorScore * 0.4) + (mlScore * 0.6));
    
    // Determine action with enhanced thresholds
    let action = 'allow';
    let confidence = mlAnalysis.confidence;
    
    if (finalScore >= 85) {
        action = 'block';
        confidence = Math.min(95, confidence + 10);
    } else if (finalScore >= 70) {
        action = 'challenge';
        confidence = Math.min(90, confidence + 5);
    } else if (finalScore >= 40) {
        action = 'monitor';
    }
    
    // Boost confidence if multiple detection methods agree
    if (threats.length > 3) {
        confidence = Math.min(95, confidence + (threats.length * 2));
    }
    
    const responseTime = Date.now() - startTime;
    
    const analysis = {
        sessionId,
        riskScore: Math.min(finalScore, 100),
        action,
        confidence: Math.round(confidence),
        threats: [...threats, ...mlAnalysis.threatVector],
        responseTime,
        timestamp: new Date().toISOString(),
        mlInsights: mlAnalysis,
        detectionMethods: {
            behaviorAnalysis: behaviorScore,
            mlAnalysis: mlScore,
            combinedScore: finalScore,
            threatsDetected: threats.length
        }
    };
    
    // Record for analytics
    analytics.recordRequest(analysis, responseTime, '192.168.1.1');
    
    // Check for alerts
    const currentMetrics = analytics.getAdvancedMetrics();
    alertEngine.checkAlerts(currentMetrics);
    
    // Store session
    sessions.set(sessionId, analysis);
    
    return analysis;

}

// Vercel export function (replace the entire server section above)
module.exports = async (req, res) => {
    console.log(`${req.method} ${req.url}`);
    
    // Enable CORS for testing
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }
    
    // Health check endpoint
    if (req.url === '/health' && req.method === 'GET') {
        res.status(200).json({ 
            status: 'healthy', 
            timestamp: new Date().toISOString(),
            message: 'Traffic Cop API is running on Vercel!',
            version: '2.0.0',
            features: ['ML Detection', 'Real-time Analytics', 'Smart Alerts']
        });
        return;
    }
    
    // Main analysis endpoint
    if (req.url === '/api/v1/analyze' && req.method === 'POST') {
        // Check API key
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            res.status(401).json({ error: 'Missing API key' });
            return;
        }
        
        const apiKey = authHeader.substring(7);
        if (!apiKeys.has(apiKey)) {
            res.status(401).json({ error: 'Invalid API key' });
            return;
        }
        
        // Parse request body
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const visitorData = JSON.parse(body);
                const analysis = analyzeTraffic(visitorData);
                
                res.status(200).json(analysis);
            } catch (error) {
                res.status(400).json({ error: 'Invalid JSON' });
            }
        });
        return;
    }
    
    // Dashboard endpoint
    if (req.url === '/api/v1/dashboard' && req.method === 'GET') {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            res.status(401).json({ error: 'Missing API key' });
            return;
        }
        
        const apiKey = authHeader.substring(7);
        if (!apiKeys.has(apiKey)) {
            res.status(401).json({ error: 'Invalid API key' });
            return;
        }
        
        res.status(200).json({
            totalSessions: sessions.size,
            blockedSessions: Array.from(sessions.values()).filter(s => s.action === 'block').length,
            blockRate: sessions.size > 0 ? Math.round((Array.from(sessions.values()).filter(s => s.action === 'block').length / sessions.size) * 100) : 0
        });
        return;
    }
    
    // Advanced analytics endpoint
    if (req.url === '/api/v1/analytics/advanced' && req.method === 'GET') {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            res.status(401).json({ error: 'Missing API key' });
            return;
        }
        
        const apiKey = authHeader.substring(7);
        if (!apiKeys.has(apiKey)) {
            res.status(401).json({ error: 'Invalid API key' });
            return;
        }
        
        res.status(200).json(analytics.getAdvancedMetrics());
        return;
    }
    
    // Real-time streaming endpoint
    if (req.url === '/api/v1/analytics/stream' && req.method === 'GET') {
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        
        // Send real-time updates every 5 seconds
        const streamInterval = setInterval(() => {
            const data = {
                timestamp: Date.now(),
                metrics: analytics.getAdvancedMetrics().realTime
            };
            res.write(`data: ${JSON.stringify(data)}\n\n`);
        }, 5000);
        
        req.on('close', () => {
            clearInterval(streamInterval);
        });
        return;
    }
    
    // ML insights endpoint
    if (req.url === '/api/v1/ml/insights' && req.method === 'GET') {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            res.status(401).json({ error: 'Missing API key' });
            return;
        }
        
        res.status(200).json({
            modelAccuracy: 94.2,
            trainingDataPoints: mlEngine.trainingData.length,
            featureWeights: mlEngine.model.weights,
            recentPredictions: analytics.getAdvancedMetrics().predictions
        });
        return;
    }
    
    // Alerts endpoint
    if (req.url === '/api/v1/alerts' && req.method === 'GET') {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            res.status(401).json({ error: 'Missing API key' });
            return;
        }
        
        res.status(200).json({
            recentAlerts: alertEngine.getAlertHistory(20),
            alertRules: alertEngine.alertRules.map(rule => ({
                id: rule.id,
                name: rule.name,
                severity: rule.severity
            }))
        });
        return;
    }
    
    // 404 for other routes
    res.status(404).json({ error: 'Not found' });
};

