import Cocoa
import CoreLocation
import CoreWLAN
import Foundation

func securityName(_ security: CWSecurity) -> String {
    switch security {
    case .none: return "Open"
    case .WEP: return "WEP"
    case .wpaPersonal: return "WPA Personal"
    case .wpaPersonalMixed: return "WPA Personal Mixed"
    case .wpa2Personal: return "WPA2 Personal"
    case .personal: return "Personal"
    case .dynamicWEP: return "Dynamic WEP"
    case .wpaEnterprise: return "WPA Enterprise"
    case .wpaEnterpriseMixed: return "WPA Enterprise Mixed"
    case .wpa2Enterprise: return "WPA2 Enterprise"
    case .enterprise: return "Enterprise"
    case .wpa3Personal: return "WPA3 Personal"
    case .wpa3Enterprise: return "WPA3 Enterprise"
    case .wpa3Transition: return "WPA2/WPA3 Personal"
    case .OWE: return "OWE"
    case .oweTransition: return "OWE Transition"
    case .unknown: return "Unknown"
    @unknown default: return "Unknown"
    }
}

func securityName(_ network: CWNetwork) -> String {
    let candidates: [CWSecurity] = [
        .wpa3Personal, .wpa3Enterprise, .wpa3Transition,
        .wpa2Personal, .wpa2Enterprise,
        .wpaPersonal, .wpaPersonalMixed, .wpaEnterprise, .wpaEnterpriseMixed,
        .personal, .enterprise, .dynamicWEP, .WEP,
        .OWE, .oweTransition, .none,
    ]
    for sec in candidates where network.supportsSecurity(sec) {
        return securityName(sec)
    }
    return "Unknown"
}

class AppDelegate: NSObject, NSApplicationDelegate, CLLocationManagerDelegate {
    var locationManager: CLLocationManager?

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        locationManager = CLLocationManager()
        locationManager?.delegate = self
        locationManager?.requestAlwaysAuthorization()
    }

    func locationManager(_ manager: CLLocationManager, didChangeAuthorization status: CLAuthorizationStatus) {
        // Fires once at launch with .notDetermined — keep waiting for the
        // user's answer to the permission popup instead of treating it as denied.
        if status == .notDetermined {
            return
        }

        if status == .authorizedAlways || status == .authorized {
            guard let interface = CWWiFiClient.shared().interface() else {
                print(toJSON(["error": "no wifi interface found"]))
                NSApp.terminate(nil)
                return
            }

            do {
                let networks = try interface.scanForNetworks(withName: nil)

                let accessPoints: [[String: Any]] = networks
                    .sorted { $0.rssiValue > $1.rssiValue } // strongest signal first
                    .map { network in
                        [
                            "ssid":     network.ssid   ?? "<hidden>",
                            "bssid":    network.bssid  ?? "unknown",
                            "rssi":     network.rssiValue,
                            "channel":  network.wlanChannel?.channelNumber ?? -1,
                            "security": securityName(network),
                        ]
                    }

                var output: [String: Any] = [
                    "interface":    interface.interfaceName ?? "unknown",
                    "access_points": accessPoints
                ]

                // Currently associated network, if any
                if let ssid = interface.ssid() {
                    output["current_connection"] = [
                        "ssid":     ssid,
                        "bssid":    interface.bssid() ?? "unknown",
                        "rssi":     interface.rssiValue(),
                        "channel":  interface.wlanChannel()?.channelNumber ?? -1,
                        "security": securityName(interface.security()),
                    ] as [String: Any]
                } else {
                    output["current_connection"] = NSNull()
                }

                if let jsonData = try? JSONSerialization.data(withJSONObject: output, options: .prettyPrinted),
                   let jsonString = String(data: jsonData, encoding: .utf8) {
                    print(jsonString)
                } else {
                    print(toJSON(["error": "failed to serialize JSON"]))
                }

            } catch {
                print(toJSON(["error": "scan failed: \(error.localizedDescription)"]))
            }

            NSApp.terminate(nil)

        } else {
            print(toJSON(["error": "location services denied"]))
            NSApp.terminate(nil)
        }
    }

    func toJSON(_ dict: [String: String]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted),
              let str = String(data: data, encoding: .utf8) else {
            return #"{"error": "json serialization failed"}"#
        }
        return str
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
