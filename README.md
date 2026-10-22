# Kids Drawing: Toddler Paint 🎨

[![Flutter](https://img.shields.io/badge/Flutter-3.x-blue.svg)](https://flutter.dev)
[![COPPA](https://img.shields.io/badge/COPPA-Compliant-green.svg)](https://www.ftc.gov/legal-library/browse/rules/childrens-online-privacy-protection-rule-coppa)
[![Google Play Families](https://img.shields.io/badge/Google_Play-Families_Policy-orange.svg)](https://support.google.com/googleplay/android-developer/answer/9893335)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A COPPA and Google Play Families compliant Flutter drawing application designed for toddlers and young children. Built with child-safe monetization, stroke protection, and parental gates.

## 🧒 Why This Project?

Most drawing apps for kids are cluttered with aggressive, misclick-prone ads. **Kids Drawing: Toddler Paint** solves this by combining a smooth, toddler-friendly canvas with a **zero-interruption ad model**: full-screen ads are disabled while a child is drawing, banner ads have a physical safe buffer, and every external link or rewarded ad is locked behind an arithmetic **Parental Gate**. The result is a creative space that respects both the child's attention and the parent's trust.

## ✨ Key Features

- **Kid-Safe Canvas:** Smooth toddler finger painting, rainbow brushes, neon glow pens, and animal coloring templates.
- **Stroke Suppression Sentinel:** Full-screen ads are strictly blocked while the child has their finger on the canvas to prevent interruptions.
- **Physical Safe Buffer:** Bottom-anchored banner ads include a dedicated physical separation buffer to eliminate accidental toddler misclicks.
- **Parental Gate Challenge:** Arithmetic verification (e.g., `4 + 3 = ?`) protects bonus coloring page unlocks, external links, and rewarded video ads.
- **Offline-First:** Drawings are saved locally on the device; no artwork is ever uploaded to a remote server.

## 🛡️ Policy & COPPA Compliance

This application adheres to the **Google Play Families Policy**, **FTC COPPA**, and **GDPR-K**. The core compliance logic lives in `lib/ad_helper.dart`:

| Protection | Implementation |
| :--- | :--- |
| **Child-Directed Flag** | `tagForChildDirectedTreatment: TagForChildDirectedTreatment.yes` |
| **Age Rating Ceiling** | `maxAdContentRating: MaxAdContentRating.g` (strictly G-rated ads) |
| **European Underage Protection** | `tagForUnderAgeOfConsent: TagForUnderAgeOfConsent.yes` |
| **Non-Personalized Ads (NPA)** | All ad requests enforce `extras: {'npa': '1'}` with zero user profiling or tracking. |
| **Parental Consent** | Arithmetic gate before any external link, rewarded ad, or bonus unlock. |

For a full breakdown, see [`COPPA_CHECKLIST.md`](COPPA_CHECKLIST.md) and [`privacy-policy.html`](privacy-policy.html).

## 🏗️ Project Structure

| File | Purpose |
| :--- | :--- |
| `lib/ad_helper.dart` | AdMob singleton manager with COPPA `RequestConfiguration` |
| `lib/main.dart` | Drawing pad UI, stroke sentinel, safe banner dock, & parental gate |
| `android/app/src/main/AndroidManifest.xml` | Production AdMob Application ID configuration |
| `android/app/build.gradle` | Release signing wiring and R8 code shrinking rules |
| `android/app/proguard-rules.pro` | Google Mobile Ads R8 preservation rules |
| `android/key.properties.example` | Keystore credentials template |
| `pubspec.yaml` | Flutter dependencies and launcher icons configuration |
| `test/admob_coppa_test.dart` | 12/12 automated unit and invariant test suite |
| `COPPA_CHECKLIST.md` | Play Console Families audit checklist |

## 🚀 Getting Started

### Prerequisites

- Flutter SDK (3.x or later)
- Android Studio / VS Code with the Flutter plugin
- A Google AdMob account (for production ad unit IDs)

### Installation

```bash
git clone https://github.com/navyask911/VibeSync-kids-drawing-toddler-paint.git
cd VibeSync-kids-drawing-toddler-paint
flutter pub get
