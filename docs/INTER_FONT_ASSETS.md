# Inter font resources

The SafeMobile Figma theme specification names **Inter** as the application UI font.

The app already bundles the official Inter variable TrueType font:

- Resource: `app/src/main/res/font/inter_variable.ttf`
- Upstream: [rsms/inter — InterVariable.ttf](https://github.com/rsms/inter/blob/master/docs/font-files/InterVariable.ttf)
- Font weights mapped by Compose: 400 Regular, 500 Medium, 600 SemiBold, 700 Bold
- License: SIL Open Font License 1.1, retained in `app/src/main/assets/licenses/Inter-OFL.txt`

The bundled font is the upstream Inter variable TTF (879,708 bytes); its Git blob SHA matches the upstream Inter project file. No extra static files such as `inter_regular.ttf`, `inter_medium.ttf`, or `inter_bold.ttf` are required.

`ui/theme/Type.kt` maps `R.font.inter_variable` to `InterFontFamily` and explicitly configures the variable weight axis for the four weights above. Typography is rendered locally and offline. Android's SansSerif font fallback remains available for glyphs missing from Inter.

No font download or network access occurs at runtime.
