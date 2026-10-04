const mongoose = require('mongoose');

const ReportSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  incident_overview: { type: Object },
  executive_summary: { type: String },
  threat_actor: { type: Object },
  mitre_mapping: { type: Array },
  iocs: { type: Object },
  mitigations: { type: Array }
});

module.exports = mongoose.model('Report', ReportSchema);
