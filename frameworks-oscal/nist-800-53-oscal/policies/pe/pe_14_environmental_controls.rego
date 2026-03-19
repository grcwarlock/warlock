package nist.pe.pe_14

import rego.v1

# PE-14: Environmental Controls (Temperature and Humidity)

deny_no_temperature_monitoring contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.contains_critical_systems
	not facility.temperature_monitoring_enabled
	msg := sprintf("PE-14: Facility '%s' with critical systems does not have temperature monitoring", [facility.facility_id])
}

deny_no_humidity_monitoring contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.contains_critical_systems
	not facility.humidity_monitoring_enabled
	msg := sprintf("PE-14: Facility '%s' with critical systems does not have humidity monitoring", [facility.facility_id])
}

deny_temperature_out_of_range contains msg if {
	some sensor in input.normalized_data.physical_security.environmental_sensors
	sensor.sensor_type == "temperature"
	sensor.current_value > sensor.max_threshold
	msg := sprintf("PE-14: Temperature sensor '%s' at facility '%s' reads %v, exceeding maximum threshold of %v", [sensor.sensor_id, sensor.facility_id, sensor.current_value, sensor.max_threshold])
}

deny_humidity_out_of_range contains msg if {
	some sensor in input.normalized_data.physical_security.environmental_sensors
	sensor.sensor_type == "humidity"
	sensor.current_value > sensor.max_threshold
	msg := sprintf("PE-14: Humidity sensor '%s' at facility '%s' reads %v%%, exceeding maximum threshold of %v%%", [sensor.sensor_id, sensor.facility_id, sensor.current_value, sensor.max_threshold])
}

deny_no_alerting contains msg if {
	some sensor in input.normalized_data.physical_security.environmental_sensors
	not sensor.alerting_enabled
	msg := sprintf("PE-14: Environmental sensor '%s' (%s) does not have alerting enabled", [sensor.sensor_id, sensor.sensor_type])
}

default compliant := false

compliant if {
	count(deny_no_temperature_monitoring) == 0
	count(deny_no_humidity_monitoring) == 0
	count(deny_temperature_out_of_range) == 0
	count(deny_humidity_out_of_range) == 0
	count(deny_no_alerting) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_temperature_monitoring],
		[f | some f in deny_no_humidity_monitoring],
	),
	array.concat(
		array.concat(
			[f | some f in deny_temperature_out_of_range],
			[f | some f in deny_humidity_out_of_range],
		),
		[f | some f in deny_no_alerting],
	),
)

result := {
	"control_id": "PE-14",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
