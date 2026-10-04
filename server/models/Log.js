const mongoose = require('mongoose');

const LogSchema = new mongoose.Schema({
  timestamp: { type: String, required: true },
  source_ip: { type: String, required: true },
  event_type: { type: String, default: "csv_log" },
  message: { type: String, required: true },
  
  // Enriched fields
  severity: { type: String, default: "info" },
  phase: { type: String, default: "Unclassified" },
  mitre_id: { type: String, default: "" },
  is_malicious: { type: Boolean, default: false },
  geo_location: { type: String, default: "Unknown" },
  is_tor: { type: Boolean, default: false },
  
  raw: { type: String }
});

module.exports = mongoose.model('Log', LogSchema);
