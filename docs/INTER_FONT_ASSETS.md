# Inter font resources

SafeMobile's Figma theme specification names **Inter** as the UI font family.

Add the official Inter static TrueType files to this Android resource directory:

- `app/src/main/res/font/inter_regular.ttf`
- `app/src/main/res/font/inter_medium.ttf`
- `app/src/main/res/font/inter_bold.ttf`

The Compose theme resolves those resource names at runtime and maps them to
`FontWeight.Normal`, `FontWeight.Medium`, and `FontWeight.Bold`. Until all three
resources are present, the app uses Android's `FontFamily.SansSerif` fallback. It does
not download fonts at runtime.

Official upstream source: https://github.com/rsms/inter
License: SIL Open Font License 1.1 (see `app/src/main/assets/licenses/Inter-OFL.txt`).
