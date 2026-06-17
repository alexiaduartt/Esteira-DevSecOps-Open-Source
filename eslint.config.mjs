// import js from "@eslint/js";
// import globals from "globals";
// import { defineConfig } from "eslint/config";

// export default defineConfig([
//   { files: ["**/*.{js,mjs,cjs}"], plugins: { js }, extends: ["js/recommended"], languageOptions: { globals: globals.node } },
//   { files: ["**/*.js"], languageOptions: { sourceType: "script" } },
// ]);

import js from "@eslint/js";
import globals from "globals";

export default [
  {
    files: ["**/*.{js,mjs,cjs}"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.node,
        ...globals.jest // Isso adiciona 'test', 'expect', 'describe', etc.
      },
    },
    rules: {
      ...js.configs.recommended.rules,
    },
  },
  {
    files: ["**/*.js"],
    languageOptions: {
      sourceType: "script"
    }
  },
];