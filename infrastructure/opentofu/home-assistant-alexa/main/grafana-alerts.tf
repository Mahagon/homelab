# Grafana Cloud alerting for the backup CronJobs.
# Authenticate with GRAFANA_URL and GRAFANA_AUTH (service-account token, Editor role).

locals {
  backup_alert_rules = {
    backup_job_failed = {
      title    = "Backup job failed"
      summary  = "A backup Job in the backup namespace exhausted its retries."
      expr     = "sum(kube_job_status_failed{namespace=\"backup\"}) > 0"
      for      = "5m"
      severity = "critical"
    }
    backup_daily_stale = {
      title    = "Daily backup stale"
      summary  = "No successful daily backup in over 52h (Sunday is skipped by design)."
      expr     = "time() - kube_cronjob_status_last_successful_time{namespace=\"backup\", cronjob=\"homelab-backup-daily\"} > 52 * 3600"
      for      = "0s"
      severity = "critical"
    }
    backup_weekly_stale = {
      title    = "Weekly backup stale"
      summary  = "No successful weekly (HDD) backup in over 8 days."
      expr     = "time() - kube_cronjob_status_last_successful_time{namespace=\"backup\", cronjob=\"homelab-backup-weekly\"} > 8 * 24 * 3600"
      for      = "0s"
      severity = "warning"
    }
    backup_metrics_missing = {
      title    = "Backup metrics missing"
      summary  = "Backup CronJob metrics are absent (kube-state-metrics or Alloy down?)."
      expr     = "absent(kube_cronjob_status_last_successful_time{namespace=\"backup\", cronjob=\"homelab-backup-daily\"})"
      for      = "1h"
      severity = "warning"
    }
  }
}

resource "grafana_folder" "homelab" {
  title = "Homelab"
}

resource "grafana_contact_point" "homelab_email" {
  name = "homelab-email"

  email {
    addresses = [var.budget_email]
  }
}

# Singleton: replaces the whole notification policy tree of the Grafana stack.
resource "grafana_notification_policy" "homelab" {
  contact_point = grafana_contact_point.homelab_email.name
  group_by      = ["alertname"]
}

resource "grafana_rule_group" "backup" {
  name             = "homelab-backup"
  folder_uid       = grafana_folder.homelab.uid
  interval_seconds = 300

  dynamic "rule" {
    for_each = local.backup_alert_rules

    content {
      name           = rule.value.title
      condition      = "C"
      for            = rule.value.for
      no_data_state  = "OK"
      exec_err_state = "Error"

      labels = {
        severity = rule.value.severity
      }

      annotations = {
        summary = rule.value.summary
      }

      data {
        ref_id         = "A"
        datasource_uid = var.grafana_prometheus_datasource_uid

        relative_time_range {
          from = 600
          to   = 0
        }

        model = jsonencode({
          refId   = "A"
          expr    = rule.value.expr
          instant = true
        })
      }

      data {
        ref_id         = "B"
        datasource_uid = "__expr__"

        relative_time_range {
          from = 600
          to   = 0
        }

        model = jsonencode({
          refId      = "B"
          type       = "reduce"
          expression = "A"
          reducer    = "last"
          settings   = { mode = "dropNN" }
        })
      }

      data {
        ref_id         = "C"
        datasource_uid = "__expr__"

        relative_time_range {
          from = 600
          to   = 0
        }

        model = jsonencode({
          refId      = "C"
          type       = "threshold"
          expression = "B"
          conditions = [{
            evaluator = { type = "gt", params = [0] }
          }]
        })
      }
    }
  }
}
