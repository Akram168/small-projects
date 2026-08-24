#!/usr/bin/env python3
"""
Weather CLI: looks up a place name, geocodes it, and prints the current
weather. Uses the free Open-Meteo API -- no API key required.

Usage:
  python weather.py "London"
  python weather.py "New York" --units imperial
"""

import argparse
import json
import sys
import urllib.parse
import urllib.request

GEOCODE_URL = "https://geocoding-api.open-meteo.com/v1/search"
WEATHER_URL = "https://api.open-meteo.com/v1/forecast"

WEATHER_CODES = {
    0: "Clear sky", 1: "Mainly clear", 2: "Partly cloudy", 3: "Overcast",
    45: "Fog", 48: "Depositing rime fog",
    51: "Light drizzle", 53: "Moderate drizzle", 55: "Dense drizzle",
    61: "Slight rain", 63: "Moderate rain", 65: "Heavy rain",
    71: "Slight snow", 73: "Moderate snow", 75: "Heavy snow",
    80: "Slight rain showers", 81: "Moderate rain showers", 82: "Violent rain showers",
    95: "Thunderstorm", 96: "Thunderstorm with slight hail", 99: "Thunderstorm with heavy hail",
}


def fetch_json(url, params):
    query = urllib.parse.urlencode(params)
    with urllib.request.urlopen(f"{url}?{query}", timeout=10) as resp:
        return json.loads(resp.read())


def geocode(place):
    data = fetch_json(GEOCODE_URL, {"name": place, "count": 1})
    results = data.get("results")
    if not results:
        return None
    r = results[0]
    return {
        "name": r["name"],
        "country": r.get("country", ""),
        "lat": r["latitude"],
        "lon": r["longitude"],
    }


def get_weather(lat, lon, units):
    temp_unit = "fahrenheit" if units == "imperial" else "celsius"
    wind_unit = "mph" if units == "imperial" else "kmh"
    data = fetch_json(WEATHER_URL, {
        "latitude": lat,
        "longitude": lon,
        "current_weather": "true",
        "temperature_unit": temp_unit,
        "windspeed_unit": wind_unit,
    })
    return data["current_weather"]


def main():
    parser = argparse.ArgumentParser(description="Weather CLI (Open-Meteo, no API key needed)")
    parser.add_argument("place", help="place name, e.g. 'London' or 'New York'")
    parser.add_argument("--units", choices=["metric", "imperial"], default="metric")
    args = parser.parse_args()

    location = geocode(args.place)
    if not location:
        print(f"Could not find a location matching '{args.place}'.", file=sys.stderr)
        sys.exit(1)

    weather = get_weather(location["lat"], location["lon"], args.units)

    temp_symbol = "°F" if args.units == "imperial" else "°C"
    wind_unit = "mph" if args.units == "imperial" else "km/h"
    description = WEATHER_CODES.get(weather["weathercode"], f"Unknown ({weather['weathercode']})")

    label = location["name"] + (f", {location['country']}" if location["country"] else "")
    print(f"\n{label}")
    print(f"  {description}")
    print(f"  Temperature: {weather['temperature']}{temp_symbol}")
    print(f"  Wind speed:  {weather['windspeed']} {wind_unit}")
    print(f"  Observed at: {weather['time']}")


if __name__ == "__main__":
    main()
