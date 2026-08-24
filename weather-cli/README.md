# Weather CLI

Look up current weather for any place name from the terminal. No API key, no signup — uses [Open-Meteo](https://open-meteo.com/), a free open-data weather API.

## Usage

```bash
python weather.py "London"
python weather.py "New York" --units imperial
```

## Example

```
$ python weather.py "London"

London, United Kingdom
  Partly cloudy
  Temperature: 17.9°C
  Wind speed:  15.8 km/h
  Observed at: 2026-08-24T22:00
```

## How it works

1. **Geocoding**: sends the place name to Open-Meteo's geocoding endpoint, which resolves it to latitude/longitude (and picks the best match — the top result).
2. **Forecast**: feeds those coordinates into the current-weather endpoint, requesting either metric or imperial units.
3. Maps the numeric WMO weather code the API returns (e.g. `3`) to a human-readable description (`Overcast`) via a lookup table.

Uses only Python's standard library (`urllib`) — no dependencies to install.
