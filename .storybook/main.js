module.exports = {
  framework: {
    name: '@storybook/html-vite',
    options: {}
  },
  stories: ['../stories/**/*.stories.@(js|mjs)'],
  addons: ['@storybook/addon-essentials'],
  core: {
    disableTelemetry: true
  }
}

