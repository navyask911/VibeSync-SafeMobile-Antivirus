# SafeMobile Branding Assets

**Release target:** SafeMobile Antivirus **v1.0.21** · version code **20261114**

The official app icon set uploaded by the project owner was imported from the repository-root archive using a path-safe GitHub Actions importer. Only selected image and adaptive-icon resources were staged; the source archive was deleted from the repository after successful extraction.

## Android launcher resources

Each density includes both the standard and round launcher icon:

| Android resource directory | Icon dimensions |
|---|---:|
| `mipmap-mdpi` | 48 × 48 |
| `mipmap-hdpi` | 72 × 72 |
| `mipmap-xhdpi` | 96 × 96 |
| `mipmap-xxhdpi` | 144 × 144 |
| `mipmap-xxxhdpi` | 192 × 192 |

Android 8.0+ adaptive launcher resources are provided in `mipmap-anydpi-v26/ic_launcher.xml` and `ic_launcher_round.xml`, with their referenced foreground/background resources included in the app resource tree.

## Google Play listing artwork

The imported 512 × 512 high-resolution artwork is stored at:

**[`docs/assets/safemobile-playstore-icon.png`](assets/safemobile-playstore-icon.png)**

![SafeMobile Google Play listing icon](assets/safemobile-playstore-icon.png)

Use this asset as the high-resolution Play Store listing icon. Review the current Google Play Console image requirements before publishing; this repository asset does not itself publish a listing.

## Source archive and cleanup

The uploaded archive was named `app_icons.zip.zip` in the repository root. The importer validated PNG signatures and expected density dimensions, checked adaptive XML references, copied the approved files, and removed the ZIP. The archive is not retained in Git.
