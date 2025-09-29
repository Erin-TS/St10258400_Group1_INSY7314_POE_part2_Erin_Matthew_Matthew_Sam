const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');

module.exports = {
    entry: './Frontend/src/index.js',
    output: {
        path: path.resolve(__dirname, 'Frontend/dist'),
        filename: 'bundle.js',
        publicPath: '/',
        clean: true
    },
    module: {
        rules: [
            {
                test: /\.(js|jsx)$/,
                exclude: /node_modules/,
                use: {
                    loader: 'babel-loader',
                    options: {
                        presets: ['@babel/preset-env', '@babel/preset-react']
                    }
                }
            },
            {
                test: /\.css$/,
                use: ['style-loader', 'css-loader']
            }
        ]
    },
    plugins: [
        new HtmlWebpackPlugin({
            template: './Frontend/public/index.html'
        })
    ],
    devServer: {
        static: {
            directory: path.join(__dirname, 'Frontend/dist')
        },
        port: 3000,
        host: 'localhost',
        historyApiFallback: true,
        hot: true,
        open: false,
        proxy: [{
            context: ['/api'],
            target: 'http://localhost:5000',
            changeOrigin: true
        }]
    },
    resolve: {
        extensions: ['.js', '.jsx']
    }
};