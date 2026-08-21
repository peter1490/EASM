/**
 * ESLint flat config.
 *
 * `eslint-config-next` ships flat configs as of 16, so they are imported
 * directly. The scaffolded config ran them through `FlatCompat.extends()`,
 * which is for *legacy* shareable configs: it handed a flat config array to
 * the eslintrc schema validator, the validation failed, and formatting that
 * failure threw `Converting circular structure to JSON` on the plugin objects
 * before a single file was linted.
 */

import nextCoreWebVitals from "eslint-config-next/core-web-vitals";
import nextTypeScript from "eslint-config-next/typescript";

const eslintConfig = [
  ...nextCoreWebVitals,
  ...nextTypeScript,
  {
    ignores: ["next-env.d.ts", ".next/**", "out/**", "build/**"],
  },
];

export default eslintConfig;
