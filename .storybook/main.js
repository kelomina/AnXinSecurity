module.exports = {
  framework: {
    name: '@storybook/html-vite',
    options: {}
  },
  stories: ['../stories/**/*.stories.@(js|mjs)'],
  core: {
    disableTelemetry: true
  }
}

