package nist.pe.pe_15

import rego.v1

# PE-15: Water Damage Protection

deny_no_water_detection contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.contains_critical_systems
	not facility.water_detection_sensors_installed
	msg := sprintf("PE-15: Facility '%s' with critical systems does not have water detection sensors", [facility.facility_id])
}

deny_no_shutoff_valves contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	not facility.water_shutoff_valves_accessible
	msg := sprintf("PE-15: Water shutoff valves at facility '%s' are not accessible to key personnel", [facility.facility_id])
}

deny_water_sensor_not_monitored contains msg if {
	some sensor in input.normalized_data.physical_security.environmental_sensors
	sensor.sensor_type == "water"
	not sensor.actively_monitored
	msg := sprintf("PE-15: Water detection sensor '%s' at facility '%s' is not actively monitored", [sensor.sensor_id, sensor.facility_id])
}

deny_no_drainage contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.below_grade
	not facility.adequate_drainage
	msg := sprintf("PE-15: Below-grade facility '%s' does not have adequate drainage systems", [facility.facility_id])
}

default compliant := false

compliant if {
	count(deny_no_water_detection) == 0
	count(deny_no_shutoff_valves) == 0
	count(deny_water_sensor_not_monitored) == 0
	count(deny_no_drainage) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_water_detection],
		[f | some f in deny_no_shutoff_valves],
	),
	array.concat(
		[f | some f in deny_water_sensor_not_monitored],
		[f | some f in deny_no_drainage],
	),
)

result := {
	"control_id": "PE-15",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
