export function bundledNotices(): {
  vitePlugin: { name: string; apply: 'build'; enforce: 'post' };
  cssPlugin: { postcssPlugin: string };
};
