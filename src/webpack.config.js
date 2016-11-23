module.exports = {
    entry: "./entry.ts",
    target: "web",
    output: {
        path: "../out/webpack",
        filename: "pe-struct.js",
        libraryTarget: "umd",
        library: "PEStruct"
    },
    devtool: "source-map",
    resolve: {
        extensions: ["", ".webpack.js", ".web.js", ".ts", ".tsx", ".js"]
    },
    module: {
        loaders: [
            { test: /\.ts$/, loader: "ts-loader" },
            { test: /\.js$/, loader: 'babel', query: { compact: false } }
        ],
        preLoaders: [
            { test: /\.js$/, loader: "source-map-loader" }
        ]
    }
};