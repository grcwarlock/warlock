output "app_id" {
  description = "Heroku application ID"
  value       = heroku_app.main.id
}

output "web_url" {
  description = "Public URL of the Heroku application"
  value       = heroku_app.main.web_url
}
