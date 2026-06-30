resource "google_project_iam_member" "bad_public_owner" {
  project = "demo-project"
  role    = "roles/owner"
  member  = "allUsers"
}

resource "google_compute_firewall" "bad_open_firewall" {
  name    = "allow-everything"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_service_account_key" "long_lived_key" {
  service_account_id = "demo@example.iam.gserviceaccount.com"
}
