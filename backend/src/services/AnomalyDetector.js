const {
  TIME,
  ANOMALY,
  LEVEL_SCORES,
  FEATURE_WEIGHTS,
  TIME_PATTERN,
  SEVERITY_RATIOS
} = require('../config/constants');

class AnomalyDetector {
  constructor(logStore, alertStore) {
    this.logStore = logStore;
    this.alertStore = alertStore;
    this.config = this.buildDefaultConfig();
    this.stats = this.createEmptyStats();
    this.baseline = this.createEmptyBaseline();
  }

  buildDefaultConfig() {
    return {
      errorRateWindow: TIME.ONE_MINUTE_MS,
      errorRateThreshold: ANOMALY.ERROR_RATE_THRESHOLD,
      errorRateMinSample: ANOMALY.ERROR_RATE_MIN_SAMPLE,
      frequencyWindow: TIME.ONE_MINUTE_MS,
      frequencyThreshold: ANOMALY.FREQUENCY_THRESHOLD,
      patternMinOccurrences: ANOMALY.PATTERN_MIN_OCCURRENCES,
      contaminationRate: ANOMALY.CONTAMINATION_RATE,
      featureWeights: { ...FEATURE_WEIGHTS }
    };
  }

  createEmptyStats() {
    return {
      totalAnalyzed: 0,
      anomaliesDetected: 0,
      byType: {
        errorBurst: 0,
        frequencySpike: 0,
        pattern: 0,
        mlBased: 0
      }
    };
  }

  createEmptyBaseline() {
    return {
      errorRates: [],
      frequencies: [],
      lastUpdated: null
    };
  }

  analyze(log) {
    this.stats.totalAnalyzed++;
    const anomalies = this.detectAllAnomalies(log);

    if (anomalies.length === 0) return null;

    this.stats.anomaliesDetected++;
    const significantAnomaly = this.selectMostSignificant(anomalies);
    this.stats.byType[significantAnomaly.type]++;

    this.createAlert(log, significantAnomaly);
    return significantAnomaly;
  }

  detectAllAnomalies(log) {
    const anomalies = [];

    const errorBurst = this.detectErrorBurst(log);
    if (errorBurst) anomalies.push(errorBurst);

    const frequencySpike = this.detectFrequencySpike(log);
    if (frequencySpike) anomalies.push(frequencySpike);

    const patternAnomaly = this.detectPatternAnomaly(log);
    if (patternAnomaly) anomalies.push(patternAnomaly);

    const mlAnomaly = this.mlBasedDetection(log);
    if (mlAnomaly) anomalies.push(mlAnomaly);

    return anomalies;
  }

  detectErrorBurst(log) {
    if (log.level !== 'error') return null;

    const recentLogs = this.getRecentLogs(this.config.errorRateWindow);
    if (recentLogs.length < this.config.errorRateMinSample) return null;

    const errorRate = this.calculateErrorRate(recentLogs);
    if (errorRate <= this.config.errorRateThreshold) return null;

    return this.buildErrorBurstResult(recentLogs, errorRate);
  }

  getRecentLogs(windowMs) {
    const windowStart = Date.now() - windowMs;
    return this.logStore.logs.filter(
      log => new Date(log.timestamp).getTime() > windowStart
    );
  }

  calculateErrorRate(logs) {
    const errorCount = logs.filter(l => l.level === 'error').length;
    return errorCount / logs.length;
  }

  buildErrorBurstResult(recentLogs, errorRate) {
    const errorCount = recentLogs.filter(l => l.level === 'error').length;
    return {
      type: 'errorBurst',
      score: errorRate,
      threshold: this.config.errorRateThreshold,
      details: {
        errorCount,
        totalLogs: recentLogs.length,
        errorRate: `${(errorRate * 100).toFixed(1)}%`,
        window: `${this.config.errorRateWindow}ms`
      },
      severity: this.calculateSeverity(errorRate, this.config.errorRateThreshold)
    };
  }

  detectFrequencySpike(log) {
    const recentFromSource = this.getRecentLogsFromSource(log);
    const currentFreq = recentFromSource.length;

    if (this.baseline.frequencies.length < ANOMALY.BASELINE_MIN_SAMPLES) {
      this.baseline.frequencies.push(currentFreq);
      return null;
    }

    const zScore = this.calculateZScore(currentFreq);
    if (zScore <= this.config.frequencyThreshold) {
      this.updateFrequencyBaseline(currentFreq);
      return null;
    }

    return this.buildFrequencySpikeResult(currentFreq, zScore);
  }

  getRecentLogsFromSource(log) {
    const windowStart = Date.now() - this.config.frequencyWindow;
    return this.logStore.logs.filter(
      l => l.source === log.source && new Date(l.timestamp).getTime() > windowStart
    );
  }

  calculateZScore(currentFreq) {
    const freqs = this.baseline.frequencies;
    const mean = freqs.reduce((sum, f) => sum + f, 0) / freqs.length;
    const variance = freqs.reduce((sum, f) => sum + Math.pow(f - mean, 2), 0) / freqs.length;
    const stdDev = Math.sqrt(variance);

    if (stdDev === 0) return 0;
    return (currentFreq - mean) / stdDev;
  }

  updateFrequencyBaseline(currentFreq) {
    this.baseline.frequencies.push(currentFreq);
    if (this.baseline.frequencies.length > ANOMALY.BASELINE_MAX_SAMPLES) {
      this.baseline.frequencies.shift();
    }
  }

  buildFrequencySpikeResult(currentFreq, zScore) {
    const { mean, stdDev } = this.calculateBaselineStatistics();

    return {
      type: 'frequencySpike',
      score: zScore,
      threshold: this.config.frequencyThreshold,
      details: {
        currentFrequency: currentFreq,
        meanFrequency: mean.toFixed(2),
        standardDeviation: stdDev.toFixed(2),
        zScore: zScore.toFixed(2)
      },
      severity: this.calculateSeverity(zScore, this.config.frequencyThreshold)
    };
  }

  calculateBaselineStatistics() {
    const freqs = this.baseline.frequencies;
    const mean = freqs.reduce((sum, f) => sum + f, 0) / freqs.length;
    const variance = freqs.reduce((sum, f) => sum + Math.pow(f - mean, 2), 0) / freqs.length;
    const stdDev = Math.sqrt(variance);
    return { mean, stdDev };
  }

  detectPatternAnomaly(log) {
    const message = log.message || '';
    if (message.length < 10) return null;

    const result = this.findMostSuspiciousPattern(message);
    if (!result || result.score <= ANOMALY.PATTERN_SCORE_THRESHOLD) return null;

    return {
      type: 'pattern',
      score: result.score,
      threshold: ANOMALY.PATTERN_SCORE_THRESHOLD,
      details: result.pattern,
      severity: this.calculateSeverity(result.score, ANOMALY.PATTERN_SCORE_THRESHOLD)
    };
  }

  findMostSuspiciousPattern(message) {
    const suspiciousPatterns = [
      { pattern: /exception|error|fail|crash/i, type: 'error_pattern', weight: 0.8 },
      { pattern: /timeout|unavailable|refused/i, type: 'availability_pattern', weight: 0.7 },
      { pattern: /unauthorized|forbidden|invalid.*token/i, type: 'security_pattern', weight: 0.9 },
      { pattern: /memory|oom|out of memory/i, type: 'resource_pattern', weight: 0.85 },
      { pattern: /slow|performance|latency/i, type: 'performance_pattern', weight: 0.6 }
    ];

    let maxScore = 0;
    let detectedPattern = null;

    for (const { pattern, type, weight } of suspiciousPatterns) {
      if (pattern.test(message)) {
        const patternCount = this.countPatternOccurrences(pattern);
        const rarity = 1 / (1 + Math.log10(patternCount + 1));
        const score = weight * rarity;

        if (score > maxScore) {
          maxScore = score;
          detectedPattern = { type, pattern: pattern.source, weight, rarity };
        }
      }
    }

    return maxScore > 0 ? { score: maxScore, pattern: detectedPattern } : null;
  }

  countPatternOccurrences(pattern) {
    return this.logStore.logs.filter(log => pattern.test(log.message || '')).length;
  }

  mlBasedDetection(log) {
    const features = this.extractFeatures(log);
    const anomalyScore = this.calculateAnomalyScore(features);

    if (anomalyScore <= ANOMALY.ML_SCORE_THRESHOLD) return null;

    return {
      type: 'mlBased',
      score: anomalyScore,
      threshold: ANOMALY.ML_SCORE_THRESHOLD,
      details: {
        features,
        featureWeights: this.config.featureWeights
      },
      severity: this.calculateSeverity(anomalyScore, ANOMALY.ML_SCORE_THRESHOLD)
    };
  }

  extractFeatures(log) {
    return {
      logLevel: LEVEL_SCORES[log.level] ?? LEVEL_SCORES.info,
      frequency: this.calculateFrequencyScore(log),
      timePattern: this.calculateTimePatternScore(log),
      messageEntropy: this.calculateEntropy(log.message || '')
    };
  }

  calculateFrequencyScore(log) {
    const recentCount = this.logStore.logs.filter(
      l => l.source === log.source &&
      Date.now() - new Date(l.timestamp).getTime() < TIME.ONE_MINUTE_MS
    ).length;
    return Math.min(recentCount / 100, 1);
  }

  calculateTimePatternScore(log) {
    const hour = new Date(log.timestamp).getHours();
    const isUnusualHour = hour >= TIME_PATTERN.UNUSUAL_HOUR_START || hour < TIME_PATTERN.UNUSUAL_HOUR_END;
    return isUnusualHour ? TIME_PATTERN.UNUSUAL_HOURS_SCORE : TIME_PATTERN.NORMAL_HOURS_SCORE;
  }

  calculateEntropy(str) {
    if (!str) return 0;

    const frequencies = this.countCharacterFrequencies(str);
    const length = str.length;

    let entropy = 0;
    for (const count of Object.values(frequencies)) {
      const probability = count / length;
      entropy -= probability * Math.log2(probability);
    }

    return Math.min(entropy / 5, 1);
  }

  countCharacterFrequencies(str) {
    const frequencies = {};
    for (const char of str) {
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    return frequencies;
  }

  calculateAnomalyScore(features) {
    const weights = this.config.featureWeights;
    return Object.entries(features).reduce(
      (score, [feature, value]) => score + value * (weights[feature] || 0),
      0
    );
  }

  calculateSeverity(score, threshold) {
    const ratio = score / threshold;
    if (ratio > SEVERITY_RATIOS.CRITICAL_MULTIPLIER) return 'critical';
    if (ratio > SEVERITY_RATIOS.HIGH_MULTIPLIER) return 'high';
    if (ratio > SEVERITY_RATIOS.MEDIUM_MULTIPLIER) return 'medium';
    return 'low';
  }

  selectMostSignificant(anomalies) {
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
    return anomalies.sort((a, b) =>
      severityOrder[b.severity] - severityOrder[a.severity] ||
      b.score - a.score
    )[0];
  }

  createAlert(log, anomaly) {
    this.alertStore.addAlert({
      type: anomaly.type,
      severity: anomaly.severity,
      title: `${anomaly.type} detected`,
      message: log.message || 'Anomaly detected in log stream',
      logId: log.id,
      source: log.source,
      service: log.service,
      details: {
        anomalyScore: anomaly.score,
        threshold: anomaly.threshold,
        anomalyDetails: anomaly.details,
        log: {
          level: log.level,
          timestamp: log.timestamp,
          message: log.message?.substring(0, 200)
        }
      }
    });
  }

  getDetectorInfo() {
    return [
      {
        name: 'Error Burst Detection',
        type: 'errorBurst',
        description: 'Detects sudden spikes in error rates using sliding window analysis',
        method: 'statistical'
      },
      {
        name: 'Frequency Spike Detection',
        type: 'frequencySpike',
        description: 'Uses Z-score analysis to detect unusual log frequency patterns',
        method: 'statistical'
      },
      {
        name: 'Pattern Anomaly Detection',
        type: 'pattern',
        description: 'Identifies suspicious patterns in log messages with rarity scoring',
        method: 'statistical'
      },
      {
        name: 'ML-Based Detection',
        type: 'mlBased',
        description: 'Feature-based anomaly scoring using weighted isolation concept',
        method: 'machine-learning'
      }
    ];
  }

  getConfig() {
    return { ...this.config };
  }

  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
  }

  getStats() {
    return { ...this.stats };
  }
}

module.exports = AnomalyDetector;
